/*
 * Copyright 2020-2021 the original author or authors.
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

import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor.ACTIVE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.USERNAME;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;
import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Introspection.
 *
 * @author Gerardo Roza
 * @since 0.1.1
 * @see OAuth2TokenIntrospectionAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section 2.1 - Introspection Request</a>
 */
public class OAuth2TokenIntrospectionAuthenticationProvider implements AuthenticationProvider {
	private final OAuth2AuthorizationService authorizationService;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 */
	public OAuth2TokenIntrospectionAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = (OAuth2TokenIntrospectionAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(
				tokenIntrospectionAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService
				.findByToken(tokenIntrospectionAuthentication.getTokenValue(), null);
		if (authorization == null) {
			return generateAuthenticationTokenForInvalidToken(clientPrincipal, registeredClient);
		}

		Token<AbstractOAuth2Token> tokenHolder = authorization
				.getToken(tokenIntrospectionAuthentication.getTokenValue());

		if (tokenHolder.isInvalidated()) {
			return generateAuthenticationTokenForInvalidToken(clientPrincipal, registeredClient);
		}

		if (isExpired(tokenHolder.getToken())
				|| (tokenHolder.getClaims() != null && hasInvalidClaims(tokenHolder.getClaims()))) {
			return generateAuthenticationTokenForInvalidToken(clientPrincipal, registeredClient);
		}

		Map<String, Object> claims = generateTokenIntrospectionClaims(
				tokenHolder, registeredClient.getClientId(), authorization.getPrincipalName());

		return new OAuth2TokenIntrospectionAuthenticationToken(clientPrincipal, claims);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private boolean isExpired(AbstractOAuth2Token token) {
		Instant expiry = token.getExpiresAt();
		return (expiry != null && Instant.now().isAfter(expiry));
	}

	private boolean hasInvalidClaims(Map<String, Object> claims) {
		Object notBeforeValue = claims.get(JwtClaimNames.NBF);
		if (notBeforeValue != null && Instant.class.isAssignableFrom(notBeforeValue.getClass())) {
			Instant notBefore = (Instant) notBeforeValue;
			return Instant.now().isBefore(notBefore);
		}
		return false;
	}

	private Map<String, Object> generateTokenIntrospectionClaims(Token<? extends AbstractOAuth2Token> tokenHolder,
			String clientId, String username) {
		Map<String, Object> claims = Optional.ofNullable(tokenHolder.getClaims()).map(LinkedHashMap::new)
				.orElse(new LinkedHashMap<>());
		AbstractOAuth2Token token = tokenHolder.getToken();
		claims.put(ACTIVE, true);
		claims.put(CLIENT_ID, clientId);
		claims.put(USERNAME, username);
		Optional.ofNullable(token.getIssuedAt()).ifPresent(iat -> claims.put(IAT, iat));
		Optional.ofNullable(token.getExpiresAt()).ifPresent(exp -> claims.put(EXP, exp));
		if (OAuth2AccessToken.class.isAssignableFrom(token.getClass())) {
			Collection<String> scopes = ((OAuth2AccessToken) token).getScopes();
			if (!scopes.isEmpty()) {
				claims.put(SCOPE, String.join(" ", scopes));
			}
			claims.put(TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER);
		}
		return claims;
	}

	private OAuth2TokenIntrospectionAuthenticationToken generateAuthenticationTokenForInvalidToken(
			Authentication clientPrincipal, RegisteredClient registeredClient) {
		return new OAuth2TokenIntrospectionAuthenticationToken(clientPrincipal, null);
	}
}
