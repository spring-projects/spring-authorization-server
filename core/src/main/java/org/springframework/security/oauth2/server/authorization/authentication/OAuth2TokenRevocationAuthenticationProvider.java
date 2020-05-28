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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenRevocationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Token Revocation.
 *
 * @author Vivek Babu
 * @since 0.0.1
 * @see OAuth2TokenRevocationAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenRevocationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7009#section-2.1">Section 2.1 Revocation Request</a>
 */
public class OAuth2TokenRevocationAuthenticationProvider implements AuthenticationProvider {

	private OAuth2AuthorizationService authorizationService;
	private OAuth2TokenRevocationService tokenRevocationService;

	/**
	 * Constructs an {@code OAuth2TokenRevocationAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param tokenRevocationService the token revocation service
	 */
	public OAuth2TokenRevocationAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenRevocationService tokenRevocationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenRevocationService, "tokenRevocationService cannot be null");
		this.authorizationService = authorizationService;
		this.tokenRevocationService = tokenRevocationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenRevocationAuthenticationToken tokenRevocationAuthenticationToken =
				(OAuth2TokenRevocationAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(tokenRevocationAuthenticationToken.getPrincipal()
				.getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) tokenRevocationAuthenticationToken.getPrincipal();
		}
		if (clientPrincipal == null || !clientPrincipal.isAuthenticated()) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		final RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		final String tokenTypeHint = tokenRevocationAuthenticationToken.getTokenTypeHint();
		final String token = tokenRevocationAuthenticationToken.getToken();
		final OAuth2Authorization authorization = authorizationService.findByTokenAndTokenType(token,
				TokenType.ACCESS_TOKEN);

		OAuth2TokenRevocationAuthenticationToken successfulAuthentication =
				new OAuth2TokenRevocationAuthenticationToken(token, registeredClient, tokenTypeHint);

		if (authorization == null) {
			return successfulAuthentication;
		}

		if (!registeredClient.getClientId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		tokenRevocationService.revoke(token, TokenType.ACCESS_TOKEN);
		return successfulAuthentication;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenRevocationAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
