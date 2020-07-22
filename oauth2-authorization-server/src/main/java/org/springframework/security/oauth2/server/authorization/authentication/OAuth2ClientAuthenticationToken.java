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
import org.springframework.security.core.SpringSecurityCoreVersion2;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Client Authentication.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @since 0.0.1
 * @see AbstractAuthenticationToken
 * @see RegisteredClient
 * @see OAuth2ClientAuthenticationProvider
 */
public class OAuth2ClientAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
	private String clientId;
	private String clientSecret;
	private RegisteredClient registeredClient;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided parameters.
	 *
	 * @param clientId the client identifier
	 * @param clientSecret the client secret
	 */
	public OAuth2ClientAuthenticationToken(String clientId, String clientSecret) {
		super(Collections.emptyList());
		Assert.hasText(clientId, "clientId cannot be empty");
		Assert.hasText(clientSecret, "clientSecret cannot be empty");
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationToken} using the provided parameters.
	 *
	 * @param registeredClient the registered client
	 */
	public OAuth2ClientAuthenticationToken(RegisteredClient registeredClient) {
		super(Collections.emptyList());
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		this.registeredClient = registeredClient;
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.registeredClient != null ?
				this.registeredClient.getClientId() :
				this.clientId;
	}

	@Override
	public Object getCredentials() {
		return this.clientSecret;
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 *
	 * @return the {@link RegisteredClient}
	 */
	public @Nullable RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}
}
