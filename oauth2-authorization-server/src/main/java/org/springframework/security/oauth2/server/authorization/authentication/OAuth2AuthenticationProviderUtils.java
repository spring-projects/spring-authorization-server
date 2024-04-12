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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

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
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	static <T extends OAuth2Token> OAuth2Authorization invalidate(
			OAuth2Authorization authorization, T token) {

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				.token(token,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

		if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
			authorizationBuilder.token(
					authorization.getAccessToken().getToken(),
					(metadata) ->
							metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

			OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
					authorization.getToken(OAuth2AuthorizationCode.class);
			if (authorizationCode != null && !authorizationCode.isInvalidated()) {
				authorizationBuilder.token(
						authorizationCode.getToken(),
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
			}
		}
		// @formatter:on

		return authorizationBuilder.build();
	}

	static <T extends OAuth2Token> OAuth2AccessToken accessToken(OAuth2Authorization.Builder builder, T token,
			OAuth2TokenContext accessTokenContext) {

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				token.getTokenValue(), token.getIssuedAt(), token.getExpiresAt(),
				accessTokenContext.getAuthorizedScopes());
		OAuth2TokenFormat accessTokenFormat = accessTokenContext.getRegisteredClient().getTokenSettings()
				.getAccessTokenFormat();
		builder.token(accessToken, (metadata) -> {
			if (token instanceof ClaimAccessor claimAccessor) {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
			}
			metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
			metadata.put(OAuth2TokenFormat.class.getName(), accessTokenFormat.getValue());
		});

		return accessToken;
	}

}
