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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Client Authentication.
 *
 * @author Vivek Babu
 * @since 0.0.1
 * @see AbstractAuthenticationToken
 * @see RegisteredClient
 * @see OAuth2TokenRevocationAuthenticationProvider
 */
public class OAuth2TokenRevocationAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final String tokenTypeHint;
	private Authentication clientPrincipal;
	private String token;
	private RegisteredClient registeredClient;

	public OAuth2TokenRevocationAuthenticationToken(String token,
			Authentication clientPrincipal, @Nullable String tokenTypeHint) {
		super(Collections.emptyList());
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.hasText(token, "token cannot be empty");
		this.token = token;
		this.clientPrincipal = clientPrincipal;
		this.tokenTypeHint = tokenTypeHint;
	}

	public OAuth2TokenRevocationAuthenticationToken(String token,
			RegisteredClient registeredClient, @Nullable String tokenTypeHint) {
		super(Collections.emptyList());
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		Assert.hasText(token, "token cannot be empty");
		this.token = token;
		this.registeredClient = registeredClient;
		this.tokenTypeHint = tokenTypeHint;
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal != null ? this.clientPrincipal : this.registeredClient
				.getClientId();
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the token.
	 *
	 * @return the token
	 */
	public String getToken() {
		return this.token;
	}

	/**
	 * Returns the token type hint.
	 *
	 * @return the token type hint
	 */
	public String getTokenTypeHint() {
		return tokenTypeHint;
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 *
	 * @return the {@link RegisteredClient}
	 */
	public @Nullable
	RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}
}
