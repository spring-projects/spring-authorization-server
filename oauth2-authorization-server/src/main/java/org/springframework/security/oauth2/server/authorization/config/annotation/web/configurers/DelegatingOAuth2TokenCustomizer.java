/*
 * Copyright 2020-2024 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.Collections;
import java.util.List;

import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
final class DelegatingOAuth2TokenCustomizer<T extends OAuth2TokenContext> implements OAuth2TokenCustomizer<T> {

	private final List<OAuth2TokenCustomizer<T>> tokenCustomizers;

	DelegatingOAuth2TokenCustomizer(List<OAuth2TokenCustomizer<T>> tokenCustomizers) {
		Assert.notEmpty(tokenCustomizers, "tokenCustomizers cannot be empty");
		this.tokenCustomizers = Collections.unmodifiableList(tokenCustomizers);
	}

	@Override
	public void customize(T context) {
		for (OAuth2TokenCustomizer<T> tokenCustomizer : this.tokenCustomizers) {
			tokenCustomizer.customize(context);
		}
	}

}
