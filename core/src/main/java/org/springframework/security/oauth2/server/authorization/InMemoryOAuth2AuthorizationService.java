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

import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory implementation of {@link OAuth2AuthorizationService}.
 *
 * @author Krisztian Toth
 */
public final class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {
	private final List<OAuth2Authorization> authorizations;

	/**
	 * Creates an {@link InMemoryOAuth2AuthorizationService}.
	 */
	public InMemoryOAuth2AuthorizationService() {
		this(Collections.emptyList());
	}

	/**
	 * Creates an {@link InMemoryOAuth2AuthorizationService} with the provided {@link List}<{@link OAuth2Authorization}>
	 * as the in-memory store.
	 *
	 * @param authorizations a {@link List}<{@link OAuth2Authorization}> object to use as the store
	 */
	public InMemoryOAuth2AuthorizationService(List<OAuth2Authorization> authorizations) {
		Assert.notNull(authorizations, "authorizations cannot be null");
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
				.filter(authorization -> doesMatch(authorization, token, tokenType))
				.findFirst()
				.orElse(null);

	}

	private boolean doesMatch(OAuth2Authorization authorization, String token, TokenType tokenType) {
		if (tokenType.equals(TokenType.ACCESS_TOKEN)) {
			return isAccessTokenEqual(token, authorization);
		} else if (tokenType.equals(TokenType.AUTHORIZATION_CODE)) {
			return isAuthorizationCodeEqual(token, authorization);
		}
		return false;
	}

	private boolean isAccessTokenEqual(String token, OAuth2Authorization authorization) {
		return authorization.getAccessToken() != null && token.equals(authorization.getAccessToken().getTokenValue());
	}

	private boolean isAuthorizationCodeEqual(String token, OAuth2Authorization authorization) {
		return token.equals(authorization.getAttributes().get(TokenType.AUTHORIZATION_CODE.getValue()));
	}
}
