/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.util.Base64;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for the Verification {@code URI}
 * (submission of the user code)} used in the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see OAuth2DeviceVerificationAuthenticationToken
 * @see OAuth2AuthorizationConsent
 * @see OAuth2DeviceAuthorizationRequestAuthenticationProvider
 * @see OAuth2DeviceAuthorizationConsentAuthenticationProvider
 * @see OAuth2DeviceCodeAuthenticationProvider
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628">OAuth 2.0 Device Authorization Grant</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.3">Section 3.3 User Interaction</a>
 */
public final class OAuth2DeviceVerificationAuthenticationProvider implements AuthenticationProvider {

	private static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.USER_CODE);
	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder());

	private final Log logger = LogFactory.getLog(getClass());
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2AuthorizationConsentService authorizationConsentService;

	/**
	 * Constructs an {@code OAuth2DeviceVerificationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2DeviceVerificationAuthenticationProvider(
			RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.authorizationConsentService = authorizationConsentService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2DeviceVerificationAuthenticationToken deviceVerificationAuthentication =
				(OAuth2DeviceVerificationAuthenticationToken) authentication;

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				deviceVerificationAuthentication.getUserCode(), USER_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with user code");
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findById(
				authorization.getRegisteredClientId());

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		Authentication principal = (Authentication) deviceVerificationAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal)) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Did not authenticate device authorization request since principal not authenticated");
			}
			// Return the authorization request as-is where isAuthenticated() is false
			return deviceVerificationAuthentication;
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				registeredClient.getId(), principal.getName());

		Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
				currentAuthorizationConsent.getScopes() : null;

		if (requiresAuthorizationConsent(registeredClient, authorizationRequest, currentAuthorizationConsent)) {
			String state = DEFAULT_STATE_GENERATOR.generateKey();
			authorization = OAuth2Authorization.from(authorization)
					.attribute(OAuth2ParameterNames.STATE, state)
					.build();

			if (this.logger.isTraceEnabled()) {
				logger.trace("Generated authorization consent state");
			}

			this.authorizationService.save(authorization);

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Saved authorization");
			}

			return new OAuth2DeviceAuthorizationConsentAuthenticationToken(authorizationRequest.getAuthorizationUri(),
					registeredClient.getClientId(), principal, deviceVerificationAuthentication.getUserCode(), state,
					authorizationRequest.getScopes(), currentAuthorizedScopes);
		}

		OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = authorization.getToken(OAuth2DeviceCode.class);
		OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
		OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
				.principalName(principal.getName())
				.authorizedScopes(currentAuthorizedScopes)
				.token(deviceCode.getToken(), metadata -> metadata
						.put(OAuth2Authorization.Token.ACCESS_GRANTED_METADATA_NAME, true))
				.token(userCode.getToken(), metadata -> metadata
						.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
				.attribute(Principal.class.getName(), principal)
				.attributes(attrs -> attrs.remove(OAuth2ParameterNames.STATE))
				.build();
		this.authorizationService.save(updatedAuthorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization with authorized scopes");
			// This log is kept separate for consistency with other providers
			this.logger.trace("Authenticated authorization consent request");
		}

		return new OAuth2DeviceVerificationAuthenticationToken(registeredClient.getClientId(), principal,
				deviceVerificationAuthentication.getUserCode());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2DeviceVerificationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static boolean requiresAuthorizationConsent(RegisteredClient registeredClient,
			OAuth2AuthorizationRequest authorizationRequest, OAuth2AuthorizationConsent authorizationConsent) {

		if (!registeredClient.getClientSettings().isRequireAuthorizationConsent()) {
			return false;
		}

		if (authorizationConsent != null &&
				authorizationConsent.getScopes().containsAll(authorizationRequest.getScopes())) {
			return false;
		}

		return true;
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null &&
				!AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
				principal.isAuthenticated();
	}

}
