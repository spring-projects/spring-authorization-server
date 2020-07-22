/*
 * Copyright 2020 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final StringKeyGenerator accessTokenGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OAuth2AuthorizationCodeAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
				(OAuth2AuthorizationCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authorizationCodeAuthentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authorizationCodeAuthentication.getPrincipal();
		}
		if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		// TODO Authenticate public client
		// A client MAY use the "client_id" request parameter to identify itself
		// when sending requests to the token endpoint.
		// In the "authorization_code" "grant_type" request to the token endpoint,
		// an unauthenticated client MUST send its "client_id" to prevent itself
		// from inadvertently accepting a code intended for a client with a different "client_id".
		// This protects the client from substitution of the authentication code.

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				authorizationCodeAuthentication.getCode(), TokenType.AUTHORIZATION_CODE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}
		if (!clientPrincipal.getRegisteredClient().getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		if (StringUtils.hasText(authorizationRequest.getRedirectUri()) &&
				!authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		String tokenValue = this.accessTokenGenerator.generateKey();
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);		// TODO Allow configuration for access token lifespan
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				tokenValue, issuedAt, expiresAt, authorizationRequest.getScopes());

		authorization = OAuth2Authorization.from(authorization)
				.accessToken(accessToken)
				.build();
		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(
				clientPrincipal.getRegisteredClient(), clientPrincipal, accessToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
