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
package org.springframework.security.oauth2.core;

import java.time.Instant;

/**
 * TODO
 * This class is temporary and will be removed after upgrading to Spring Security 5.5.0 GA.
 *
 * @author Joe Grandja
 * @since 0.0.3
 * @see <a target="_blank" href="https://github.com/spring-projects/spring-security/pull/9146">Issue gh-9146</a>
 */
public class OAuth2RefreshToken2 extends OAuth2RefreshToken {
	private final Instant expiresAt;

	public OAuth2RefreshToken2(String tokenValue, Instant issuedAt, Instant expiresAt) {
		super(tokenValue, issuedAt);
		this.expiresAt = expiresAt;
	}

	@Override
	public Instant getExpiresAt() {
		return this.expiresAt;
	}
}
