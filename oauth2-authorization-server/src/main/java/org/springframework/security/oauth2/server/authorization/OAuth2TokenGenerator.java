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
package org.springframework.security.oauth2.server.authorization;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2Token;

/**
 * Implementations of this interface are responsible for generating an {@link OAuth2Token}
 * using the attributes contained in the {@link OAuth2TokenContext}.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2Token
 * @see OAuth2TokenContext
 * @param <T> the type of the OAuth 2.0 Token
 */
@FunctionalInterface
public interface OAuth2TokenGenerator<T extends OAuth2Token> {

	/**
	 * Generate an OAuth 2.0 Token using the attributes contained in the {@link OAuth2TokenContext},
	 * or return {@code null} if the {@link OAuth2TokenContext#getTokenType()} is not supported.
	 *
	 * @param context the context containing the OAuth 2.0 Token attributes
	 * @return an {@link OAuth2Token} or {@code null} if the {@link OAuth2TokenContext#getTokenType()} is not supported
	 */
	@Nullable
	T generate(OAuth2TokenContext context);

}
