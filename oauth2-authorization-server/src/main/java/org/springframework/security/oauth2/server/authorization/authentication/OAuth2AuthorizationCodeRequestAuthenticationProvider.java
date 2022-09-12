/*
 * Copyright 2020-2022 the original author or authors.
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
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Request (and Consent)
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationValidator
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2AuthorizationConsentService authorizationConsentService;
	private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
	private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
			new OAuth2AuthorizationCodeRequestAuthenticationValidator();
	private Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.authorizationConsentService = authorizationConsentService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		return authorizationCodeRequestAuthentication.isConsent() ?
				authenticateAuthorizationConsent(authentication) :
				authenticateAuthorizationRequest(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link OAuth2TokenGenerator} that generates the {@link OAuth2AuthorizationCode}.
	 *
	 * @param authorizationCodeGenerator the {@link OAuth2TokenGenerator} that generates the {@link OAuth2AuthorizationCode}
	 * @since 0.2.3
	 */
	public void setAuthorizationCodeGenerator(OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
		Assert.notNull(authorizationCodeGenerator, "authorizationCodeGenerator cannot be null");
		this.authorizationCodeGenerator = authorizationCodeGenerator;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@link OAuth2AuthorizationCodeRequestAuthenticationContext}
	 * and is responsible for validating specific OAuth 2.0 Authorization Request parameters
	 * associated in the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
	 * The default authentication validator is {@link OAuth2AuthorizationCodeRequestAuthenticationValidator}.
	 *
	 * <p>
	 * <b>NOTE:</b> The authentication validator MUST throw {@link OAuth2AuthorizationCodeRequestAuthenticationException} if validation fails.
	 *
	 * @param authenticationValidator the {@code Consumer} providing access to the {@link OAuth2AuthorizationCodeRequestAuthenticationContext} and is responsible for validating specific OAuth 2.0 Authorization Request parameters
	 * @since 0.4.0
	 */
	public void setAuthenticationValidator(Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator) {
		Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
		this.authenticationValidator = authenticationValidator;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@link OAuth2AuthorizationConsentAuthenticationContext}
	 * containing an {@link OAuth2AuthorizationConsent.Builder} and additional context information.
	 *
	 * <p>
	 * The following context attributes are available:
	 * <ul>
	 * <li>The {@link OAuth2AuthorizationConsent.Builder} used to build the authorization consent
	 * prior to {@link OAuth2AuthorizationConsentService#save(OAuth2AuthorizationConsent)}.</li>
	 * <li>The {@link Authentication} of type
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.</li>
	 * <li>The {@link RegisteredClient} associated with the authorization request.</li>
	 * <li>The {@link OAuth2Authorization} associated with the state token presented in the
	 * authorization consent request.</li>
	 * <li>The {@link OAuth2AuthorizationRequest} associated with the authorization consent request.</li>
	 * </ul>
	 *
	 * @param authorizationConsentCustomizer the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationConsentAuthenticationContext} containing an {@link OAuth2AuthorizationConsent.Builder}
	 */
	public void setAuthorizationConsentCustomizer(Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer) {
		Assert.notNull(authorizationConsentCustomizer, "authorizationConsentCustomizer cannot be null");
		this.authorizationConsentCustomizer = authorizationConsentCustomizer;
	}

	private Authentication authenticateAuthorizationRequest(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationCodeRequestAuthentication.getClientId());
		if (registeredClient == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, null);
		}

		OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext =
				OAuth2AuthorizationCodeRequestAuthenticationContext.with(authorizationCodeRequestAuthentication)
						.registeredClient(registeredClient)
						.build();
		this.authenticationValidator.accept(authenticationContext);

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient);
		}

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge)) {
			String codeChallengeMethod = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
			if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI,
						authorizationCodeRequestAuthentication, registeredClient, null);
			}
		} else if (registeredClient.getClientSettings().isRequireProofKey()) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI,
					authorizationCodeRequestAuthentication, registeredClient, null);
		}

		// ---------------
		// The request is valid - ensure the resource owner is authenticated
		// ---------------

		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal)) {
			// Return the authorization request as-is where isAuthenticated() is false
			return authorizationCodeRequestAuthentication;
		}

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
				.clientId(registeredClient.getClientId())
				.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
				.scopes(authorizationCodeRequestAuthentication.getScopes())
				.state(authorizationCodeRequestAuthentication.getState())
				.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
				.build();

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				registeredClient.getId(), principal.getName());

		if (requireAuthorizationConsent(registeredClient, authorizationRequest, currentAuthorizationConsent)) {
			String state = DEFAULT_STATE_GENERATOR.generateKey();
			OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
					.attribute(OAuth2ParameterNames.STATE, state)
					.build();
			this.authorizationService.save(authorization);

			Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
					currentAuthorizationConsent.getScopes() : null;

			return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
					.authorizationUri(authorizationRequest.getAuthorizationUri())
					.scopes(currentAuthorizedScopes)
					.state(state)
					.consentRequired(true)
					.build();
		}

		OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
				authorizationCodeRequestAuthentication, registeredClient, null, authorizationRequest.getScopes());
		OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
		if (authorizationCode == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the authorization code.", ERROR_URI);
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
		}

		OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
				.authorizedScopes(authorizationRequest.getScopes())
				.token(authorizationCode)
				.build();
		this.authorizationService.save(authorization);

		String redirectUri = authorizationRequest.getRedirectUri();
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}

		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.redirectUri(redirectUri)
				.scopes(authorizationRequest.getScopes())
				.state(authorizationRequest.getState())
				.authorizationCode(authorizationCode)
				.build();
	}

	private Authentication authenticateAuthorizationConsent(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				authorizationCodeRequestAuthentication.getState(), STATE_TOKEN_TYPE);
		if (authorization == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
					authorizationCodeRequestAuthentication, null, null);
		}

		// The 'in-flight' authorization must be associated to the current principal
		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal) || !principal.getName().equals(authorization.getPrincipalName())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
					authorizationCodeRequestAuthentication, null, null);
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationCodeRequestAuthentication.getClientId());
		if (registeredClient == null || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient);
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> requestedScopes = authorizationRequest.getScopes();
		Set<String> authorizedScopes = new HashSet<>(authorizationCodeRequestAuthentication.getScopes());
		if (!requestedScopes.containsAll(authorizedScopes)) {
			throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
					authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
		}

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				authorization.getRegisteredClientId(), authorization.getPrincipalName());
		Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
				currentAuthorizationConsent.getScopes() : Collections.emptySet();

		if (!currentAuthorizedScopes.isEmpty()) {
			for (String requestedScope : requestedScopes) {
				if (currentAuthorizedScopes.contains(requestedScope)) {
					authorizedScopes.add(requestedScope);
				}
			}
		}

		if (!authorizedScopes.isEmpty() && requestedScopes.contains(OidcScopes.OPENID)) {
			// 'openid' scope is auto-approved as it does not require consent
			authorizedScopes.add(OidcScopes.OPENID);
		}

		OAuth2AuthorizationConsent.Builder authorizationConsentBuilder;
		if (currentAuthorizationConsent != null) {
			authorizationConsentBuilder = OAuth2AuthorizationConsent.from(currentAuthorizationConsent);
		} else {
			authorizationConsentBuilder = OAuth2AuthorizationConsent.withId(
					authorization.getRegisteredClientId(), authorization.getPrincipalName());
		}
		authorizedScopes.forEach(authorizationConsentBuilder::scope);

		if (this.authorizationConsentCustomizer != null) {
			// @formatter:off
			OAuth2AuthorizationConsentAuthenticationContext authorizationConsentAuthenticationContext =
					OAuth2AuthorizationConsentAuthenticationContext.with(authorizationCodeRequestAuthentication)
							.authorizationConsent(authorizationConsentBuilder)
							.registeredClient(registeredClient)
							.authorization(authorization)
							.authorizationRequest(authorizationRequest)
							.build();
			// @formatter:on
			this.authorizationConsentCustomizer.accept(authorizationConsentAuthenticationContext);
		}

		Set<GrantedAuthority> authorities = new HashSet<>();
		authorizationConsentBuilder.authorities(authorities::addAll);

		if (authorities.isEmpty()) {
			// Authorization consent denied (or revoked)
			if (currentAuthorizationConsent != null) {
				this.authorizationConsentService.remove(currentAuthorizationConsent);
			}
			this.authorizationService.remove(authorization);
			throwError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
		}

		OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
		if (!authorizationConsent.equals(currentAuthorizationConsent)) {
			this.authorizationConsentService.save(authorizationConsent);
		}

		OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
				authorizationCodeRequestAuthentication, registeredClient, authorization, authorizedScopes);
		OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
		if (authorizationCode == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the authorization code.", ERROR_URI);
			throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
		}

		OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
				.authorizedScopes(authorizedScopes)
				.token(authorizationCode)
				.attributes(attrs -> {
					attrs.remove(OAuth2ParameterNames.STATE);
				})
				.build();
		this.authorizationService.save(updatedAuthorization);

		String redirectUri = authorizationRequest.getRedirectUri();
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}

		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.redirectUri(redirectUri)
				.scopes(authorizedScopes)
				.state(authorizationRequest.getState())
				.authorizationCode(authorizationCode)
				.build();
	}

	private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient, Authentication principal,
			OAuth2AuthorizationRequest authorizationRequest) {
		return OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(principal.getName())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(Principal.class.getName(), principal)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
	}

	private static OAuth2TokenContext createAuthorizationCodeTokenContext(
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2Authorization authorization, Set<String> authorizedScopes) {

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationCodeRequestAuthentication);
		// @formatter:on

		if (authorization != null) {
			tokenContextBuilder.authorization(authorization);
		}

		return tokenContextBuilder.build();
	}

	private static boolean requireAuthorizationConsent(RegisteredClient registeredClient,
			OAuth2AuthorizationRequest authorizationRequest, OAuth2AuthorizationConsent authorizationConsent) {

		if (!registeredClient.getClientSettings().isRequireAuthorizationConsent()) {
			return false;
		}
		// 'openid' scope does not require consent
		if (authorizationRequest.getScopes().contains(OidcScopes.OPENID) &&
				authorizationRequest.getScopes().size() == 1) {
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

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		throwError(errorCode, parameterName, authorizationCodeRequestAuthentication, registeredClient, null);
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		throwError(errorCode, parameterName, ERROR_URI,
				authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throwError(error, parameterName, authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
	}

	private static void throwError(OAuth2Error error, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {

		boolean redirectOnError = true;
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST) &&
				(parameterName.equals(OAuth2ParameterNames.CLIENT_ID) ||
						parameterName.equals(OAuth2ParameterNames.STATE))) {
			redirectOnError = false;
		}

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = authorizationCodeRequestAuthentication;

		if (redirectOnError && !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			String redirectUri = resolveRedirectUri(authorizationRequest, registeredClient);
			String state = authorizationCodeRequestAuthentication.isConsent() && authorizationRequest != null ?
					authorizationRequest.getState() : authorizationCodeRequestAuthentication.getState();
			authorizationCodeRequestAuthenticationResult = from(authorizationCodeRequestAuthentication)
					.redirectUri(redirectUri)
					.state(state)
					.build();
		} else if (!redirectOnError && StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			authorizationCodeRequestAuthenticationResult = from(authorizationCodeRequestAuthentication)
					.redirectUri(null)		// Prevent redirects
					.build();
		}

		authorizationCodeRequestAuthenticationResult.setAuthenticated(authorizationCodeRequestAuthentication.isAuthenticated());

		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
	}

	private static String resolveRedirectUri(OAuth2AuthorizationRequest authorizationRequest, RegisteredClient registeredClient) {
		if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
			return authorizationRequest.getRedirectUri();
		}
		if (registeredClient != null) {
			return registeredClient.getRedirectUris().iterator().next();
		}
		return null;
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken.Builder from(OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(authorizationCodeRequestAuthentication.getClientId(), (Authentication) authorizationCodeRequestAuthentication.getPrincipal())
				.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
				.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
				.scopes(authorizationCodeRequestAuthentication.getScopes())
				.state(authorizationCodeRequestAuthentication.getState())
				.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
				.authorizationCode(authorizationCodeRequestAuthentication.getAuthorizationCode());
	}

	private static class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {
		private final StringKeyGenerator authorizationCodeGenerator =
				new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

		@Nullable
		@Override
		public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
			if (context.getTokenType() == null ||
					!OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
			return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
		}

	}

}
