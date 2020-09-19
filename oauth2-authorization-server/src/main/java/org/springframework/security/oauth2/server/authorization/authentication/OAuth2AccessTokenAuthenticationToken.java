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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used when issuing an OAuth 2.0 Access Token.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @since 0.0.1
 * @see AbstractAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see RegisteredClient
 * @see OAuth2AccessToken
 * @see OAuth2ClientAuthenticationToken
 */
public class OAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final RegisteredClient registeredClient;
	private final Authentication clientPrincipal;
	private final OAuth2AccessToken accessToken;

	/**
	 * Constructs an {@code OAuth2AccessTokenAuthenticationToken} using the provided parameters.
	 *
	 * @param registeredClient the registered client
	 * @param clientPrincipal the authenticated client principal
	 * @param accessToken the access token
	 */
	public OAuth2AccessTokenAuthenticationToken(RegisteredClient registeredClient,
			Authentication clientPrincipal, OAuth2AccessToken accessToken) {
		super(Collections.emptyList());
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.notNull(accessToken, "accessToken cannot be null");
		this.registeredClient = registeredClient;
		this.clientPrincipal = clientPrincipal;
		this.accessToken = accessToken;
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 *
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}

	/**
	 * Returns the {@link OAuth2AccessToken access token}.
	 *
	 * @return the {@link OAuth2AccessToken}
	 */
	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}
}
