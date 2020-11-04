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
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenMetadata;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

/**
 * Utility methods for the OAuth 2.0 {@link AuthenticationProvider}'s.
 *
 * @author Joe Grandja
 * @since 0.0.3
 */
final class OAuth2AuthenticationProviderUtils {

	private OAuth2AuthenticationProviderUtils() {
	}

	static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
	}

	static <T extends AbstractOAuth2Token> OAuth2Authorization invalidate(
			OAuth2Authorization authorization, T token) {

		OAuth2Tokens.Builder builder = OAuth2Tokens.from(authorization.getTokens())
				.token(token, OAuth2TokenMetadata.builder().invalidated().build());

		if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
			builder.token(
					authorization.getTokens().getAccessToken(),
					OAuth2TokenMetadata.builder().invalidated().build());
			OAuth2AuthorizationCode authorizationCode =
					authorization.getTokens().getToken(OAuth2AuthorizationCode.class);
			if (authorizationCode != null &&
					!authorization.getTokens().getTokenMetadata(authorizationCode).isInvalidated()) {
				builder.token(
						authorizationCode,
						OAuth2TokenMetadata.builder().invalidated().build());
			}
		}

		return OAuth2Authorization.from(authorization)
				.tokens(builder.build())
				.build();
	}
}
