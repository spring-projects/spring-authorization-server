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
package org.springframework.security.oauth2.server.authorization.event;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;

public abstract class OAuth2TokenIssuedEvent extends OAuth2AuditEvent {
	private final OAuth2AccessTokenAuthenticationToken token;
	private final AuthorizationGrantType grantType;

	/**
	 * Create a new {@code OAuth2TokenIssuedEvent}.
	 *
	 * @param token the token
	 * @param grantType
	 */
	public OAuth2TokenIssuedEvent(OAuth2AccessTokenAuthenticationToken token, AuthorizationGrantType grantType) {
		super(token, token.getRegisteredClient());
		this.token = token;
		this.grantType = grantType;
	}

	public AuthorizationGrantType getGrantType() {
		return this.grantType;
	}

	public final OAuth2AccessTokenAuthenticationToken getToken() {
		return this.token;
	}
}
