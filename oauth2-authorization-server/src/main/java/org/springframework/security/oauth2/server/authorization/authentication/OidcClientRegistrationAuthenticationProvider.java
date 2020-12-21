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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Client Registration Endpoint.
 *
 * @author Ovidiu Popa
 * @since 0.1.1
 * @see JwtAuthenticationToken
 * @see OAuth2AuthorizationService
 */
public class OidcClientRegistrationAuthenticationProvider implements AuthenticationProvider {

	private static final String CLIENT_CREATE_SCOPE = "client.create";
	private final OAuth2AuthorizationService authorizationService;

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 */
	public OidcClientRegistrationAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		JwtAuthenticationToken jwtAuthenticationToken =
				(JwtAuthenticationToken) authentication;

		String tokenValue = jwtAuthenticationToken.getToken().getTokenValue();
		OAuth2Authorization authorization = this.authorizationService.findByToken(tokenValue, OAuth2TokenType.ACCESS_TOKEN);

		if (authorization == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		OAuth2Authorization.Token<OAuth2AccessToken> authorizationAccessToken =
				authorization.getAccessToken();
		if (authorizationAccessToken.isInvalidated()) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}
		OAuth2AccessToken accessToken = authorizationAccessToken.getToken();
		if (!accessToken.getScopes().contains(CLIENT_CREATE_SCOPE)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, accessToken);
		this.authorizationService.save(authorization);

		return jwtAuthenticationToken;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return JwtAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
