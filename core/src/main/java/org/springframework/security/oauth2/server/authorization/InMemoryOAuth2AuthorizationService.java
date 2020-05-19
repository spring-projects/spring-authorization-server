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

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * An {@link OAuth2AuthorizationService} that stores {@link OAuth2Authorization}'s in-memory.
 *
 * @author Krisztian Toth
 * @since 0.0.1
 * @see OAuth2AuthorizationService
 */
public final class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {
	private final List<OAuth2Authorization> authorizations;

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService}.
	 */
	public InMemoryOAuth2AuthorizationService() {
		this.authorizations = new CopyOnWriteArrayList<>();
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
	 *
	 * @param authorizations the initial {@code List} of {@link OAuth2Authorization}(s)
	 */
	public InMemoryOAuth2AuthorizationService(List<OAuth2Authorization> authorizations) {
		Assert.notEmpty(authorizations, "authorizations cannot be empty");
		this.authorizations = new CopyOnWriteArrayList<>(authorizations);
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		this.authorizations.add(authorization);
	}

	@Override
	public OAuth2Authorization findByTokenAndTokenType(String token, TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		Assert.notNull(tokenType, "tokenType cannot be null");
		return this.authorizations.stream()
				.filter(authorization -> hasToken(authorization, token, tokenType))
				.findFirst()
				.orElse(null);
	}

	private boolean hasToken(OAuth2Authorization authorization, String token, TokenType tokenType) {
		if (TokenType.AUTHORIZATION_CODE.equals(tokenType)) {
			return token.equals(authorization.getAttributes().get(OAuth2ParameterNames.class.getName().concat(".CODE")));
		} else if (TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return authorization.getAccessToken() != null &&
					authorization.getAccessToken().getTokenValue().equals(token);
		}
		return false;
	}
}
