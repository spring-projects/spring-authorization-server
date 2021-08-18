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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
	private final Map<String, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService}.
	 */
	public InMemoryOAuth2AuthorizationService() {
		this(Collections.emptyList());
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
	 *
	 * @param authorizations the authorization(s)
	 */
	public InMemoryOAuth2AuthorizationService(OAuth2Authorization... authorizations) {
		this(Arrays.asList(authorizations));
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
	 *
	 * @param authorizations the authorization(s)
	 */
	public InMemoryOAuth2AuthorizationService(List<OAuth2Authorization> authorizations) {
		Assert.notNull(authorizations, "authorizations cannot be null");
		authorizations.forEach(authorization -> {
			Assert.notNull(authorization, "authorization cannot be null");
			Assert.isTrue(!this.authorizations.containsKey(authorization.getId()),
					"The authorization must be unique. Found duplicate identifier: " + authorization.getId());
			this.authorizations.put(authorization.getId(), authorization);
		});
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		this.authorizations.put(authorization.getId(), authorization);
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		this.authorizations.remove(authorization.getId(), authorization);
	}

	@Nullable
	@Override
	public OAuth2Authorization findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.authorizations.get(id);
	}

	@Nullable
	@Override
	public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		for (OAuth2Authorization authorization : this.authorizations.values()) {
			if (hasToken(authorization, token, tokenType)) {
				return authorization;
			}
		}
		return null;
	}

	private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
		if (tokenType == null) {
			return matchesState(authorization, token) ||
					matchesAuthorizationCode(authorization, token) ||
					matchesAccessToken(authorization, token) ||
					matchesRefreshToken(authorization, token);
		} else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			return matchesState(authorization, token);
		} else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			return matchesAuthorizationCode(authorization, token);
		} else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return matchesAccessToken(authorization, token);
		} else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
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
}
