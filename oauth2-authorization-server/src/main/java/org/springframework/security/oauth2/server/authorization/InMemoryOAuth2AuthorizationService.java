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
package org.springframework.security.oauth2.server.authorization;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthorizationService} that stores {@link OAuth2Authorization}'s in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationService
 */
public final class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {
	private final Map<OAuth2AuthorizationId, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		OAuth2AuthorizationId authorizationId = new OAuth2AuthorizationId(
				authorization.getRegisteredClientId(), authorization.getPrincipalName());
		this.authorizations.put(authorizationId, authorization);
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		OAuth2AuthorizationId authorizationId = new OAuth2AuthorizationId(
				authorization.getRegisteredClientId(), authorization.getPrincipalName());
		this.authorizations.remove(authorizationId, authorization);
	}

	@Nullable
	@Override
	public OAuth2Authorization findByToken(String token, @Nullable TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		return this.authorizations.values().stream()
				.filter(authorization -> hasToken(authorization, token, tokenType))
				.findFirst()
				.orElse(null);
	}

	private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable TokenType tokenType) {
		if (tokenType == null) {
			return matchesState(authorization, token) ||
					matchesAuthorizationCode(authorization, token) ||
					matchesAccessToken(authorization, token) ||
					matchesRefreshToken(authorization, token);
		} else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			return matchesState(authorization, token);
		} else if (TokenType.AUTHORIZATION_CODE.equals(tokenType)) {
			return matchesAuthorizationCode(authorization, token);
		} else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return matchesAccessToken(authorization, token);
		} else if (TokenType.REFRESH_TOKEN.equals(tokenType)) {
			return matchesRefreshToken(authorization, token);
		}
		return false;
	}

	private static boolean matchesState(OAuth2Authorization authorization, String token) {
		return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
	}

	private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
				authorization.getToken(OAuth2AuthorizationCode.class);
		return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
	}

	private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
				authorization.getToken(OAuth2AccessToken.class);
		return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
	}

	private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
				authorization.getToken(OAuth2RefreshToken.class);
		return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
	}

	private static class OAuth2AuthorizationId implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		private final String registeredClientId;
		private final String principalName;

		private OAuth2AuthorizationId(String registeredClientId, String principalName) {
			this.registeredClientId = registeredClientId;
			this.principalName = principalName;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || getClass() != obj.getClass()) {
				return false;
			}
			OAuth2AuthorizationId that = (OAuth2AuthorizationId) obj;
			return Objects.equals(this.registeredClientId, that.registeredClientId) &&
					Objects.equals(this.principalName, that.principalName);
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.registeredClientId, this.principalName);
		}
	}
}
