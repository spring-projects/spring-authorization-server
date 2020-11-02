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

/**
 * Basic interface to allow customization of tokens issued by {@link OAuth2TokenIssuer}.
 *
 * @author Alexey Nesterov
 * @since 0.1.0
 */
@FunctionalInterface
public interface OAuth2TokenCustomizer<T extends OAuth2TokenBuilder<?>> {

	/**
	 * Apply token customization before it is issued by the issuer.
	 *
	 * @see JwtBuilder
	 *
	 * @param tokenBuilder that the issuer is willing to share with the customizer.
	 */
	void customize(T tokenBuilder);

}
