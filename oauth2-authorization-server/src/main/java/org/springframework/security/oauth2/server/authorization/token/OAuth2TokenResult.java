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

package org.springframework.security.oauth2.server.authorization.token;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;

/**
 * Result returned by a {@link OAuth2TokenIssuer}, a combination of a token of {@code T} type and {@link OAuth2TokenMetadata}.
 *
 * @see OAuth2TokenIssuer
 * @see OAuth2TokenMetadata
 *
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class OAuth2TokenResult<T extends AbstractOAuth2Token> {

	private final T token;
	private final OAuth2TokenMetadata metadata;

	private OAuth2TokenResult(T token, OAuth2TokenMetadata metadata) {
		this.token = token;
		this.metadata = metadata;
	}

	/**
	 * Create new token result.
	 *
	 * @param token original token
	 * @param metadata metadata
	 * @param <T> type of the original token
	 * @return a new {@code OAuth2TokenResult}
	 */
	public static <T extends AbstractOAuth2Token> OAuth2TokenResult<T> of(T token, OAuth2TokenMetadata metadata) {
		return new OAuth2TokenResult<>(token, metadata);
	}

	/**
	 * Get the original token.
	 *
	 * @return token of type {@code T}
	 */
	public T getToken() {
		return token;
	}

	/**
	 * Get metadata associated with the token
	 *
	 * @return token metadata
	 */
	public OAuth2TokenMetadata getMetadata() {
		return this.metadata;
	}
}
