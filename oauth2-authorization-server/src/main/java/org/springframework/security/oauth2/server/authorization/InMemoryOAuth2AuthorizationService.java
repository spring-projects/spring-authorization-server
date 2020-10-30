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
package org.springframework.security.oauth2.server.authorization;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An {@link OAuth2AuthorizationService} that stores {@link OAuth2Authorization}'s in-memory.
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

	@Override
	public OAuth2Authorization findByToken(String token, @Nullable TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		return this.authorizations.values().stream()
				.filter(authorization -> hasToken(authorization, token, tokenType))
				.findFirst()
				.orElse(null);
	}

	private boolean hasToken(OAuth2Authorization authorization, String token, TokenType tokenType) {
		if (OAuth2AuthorizationAttributeNames.STATE.equals(tokenType.getValue())) {
			return token.equals(authorization.getAttribute(OAuth2AuthorizationAttributeNames.STATE));
		} else if (TokenType.AUTHORIZATION_CODE.equals(tokenType)) {
			OAuth2AuthorizationCode authorizationCode = authorization.getTokens().getToken(OAuth2AuthorizationCode.class);
			return authorizationCode != null && authorizationCode.getTokenValue().equals(token);
		} else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return authorization.getTokens().getAccessToken() != null &&
					authorization.getTokens().getAccessToken().getTokenValue().equals(token);
		} else if (TokenType.REFRESH_TOKEN.equals(tokenType)) {
			return authorization.getTokens().getRefreshToken() != null &&
					authorization.getTokens().getRefreshToken().getTokenValue().equals(token);
		}

		return false;
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
