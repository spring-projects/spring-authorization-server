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

import java.net.URL;
import java.time.Instant;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

/**
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Introspection.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @author Gaurav Tiwari
 * @since 0.1.1
 * @see OAuth2TokenIntrospectionAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section 2.1 Introspection Request</a>
 */
public final class OAuth2TokenIntrospectionAuthenticationProvider implements AuthenticationProvider {
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OAuth2TokenIntrospectionAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication =
				(OAuth2TokenIntrospectionAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(tokenIntrospectionAuthentication);

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				tokenIntrospectionAuthentication.getToken(), null);
		if (authorization == null) {
			// Return the authentication request when token not found
			return tokenIntrospectionAuthentication;
		}

		OAuth2Authorization.Token<AbstractOAuth2Token> authorizedToken =
				authorization.getToken(tokenIntrospectionAuthentication.getToken());
		if (!authorizedToken.isActive()) {
			return new OAuth2TokenIntrospectionAuthenticationToken(tokenIntrospectionAuthentication.getToken(),
					clientPrincipal, OAuth2TokenIntrospection.builder().build());
		}

		RegisteredClient authorizedClient = this.registeredClientRepository.findById(authorization.getRegisteredClientId());
		OAuth2TokenIntrospection tokenClaims = withActiveTokenClaims(authorizedToken, authorizedClient);

		return new OAuth2TokenIntrospectionAuthenticationToken(authorizedToken.getToken().getTokenValue(),
				clientPrincipal, tokenClaims);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static OAuth2TokenIntrospection withActiveTokenClaims(
			OAuth2Authorization.Token<AbstractOAuth2Token> authorizedToken, RegisteredClient authorizedClient) {

		OAuth2TokenIntrospection.Builder tokenClaims = OAuth2TokenIntrospection.builder(true)
				.clientId(authorizedClient.getClientId());

		// TODO Set "username"

		AbstractOAuth2Token token = authorizedToken.getToken();
		if (token.getIssuedAt() != null) {
			tokenClaims.issuedAt(token.getIssuedAt());
		}
		if (token.getExpiresAt() != null) {
			tokenClaims.expiresAt(token.getExpiresAt());
		}

		if (OAuth2AccessToken.class.isAssignableFrom(token.getClass())) {
			OAuth2AccessToken accessToken = (OAuth2AccessToken) token;
			tokenClaims.scopes(scopes -> scopes.addAll(accessToken.getScopes()));
			tokenClaims.tokenType(accessToken.getTokenType().getValue());

			if (!CollectionUtils.isEmpty(authorizedToken.getClaims())) {
				OAuth2TokenClaimAccessor accessTokenClaims = authorizedToken::getClaims;

				Instant notBefore = accessTokenClaims.getNotBefore();
				if (notBefore != null) {
					tokenClaims.notBefore(notBefore);
				}
				tokenClaims.subject(accessTokenClaims.getSubject());
				List<String> audience = accessTokenClaims.getAudience();
				if (!CollectionUtils.isEmpty(audience)) {
					tokenClaims.audiences(audiences -> audiences.addAll(audience));
				}
				URL issuer = accessTokenClaims.getIssuer();
				if (issuer != null) {
					tokenClaims.issuer(issuer.toExternalForm());
				}
				String jti = accessTokenClaims.getId();
				if (StringUtils.hasText(jti)) {
					tokenClaims.id(jti);
				}
			}
		}

		tokenClaims.withCustomClaims(authorizedToken.getClaims());

		return tokenClaims.build();
	}
}
