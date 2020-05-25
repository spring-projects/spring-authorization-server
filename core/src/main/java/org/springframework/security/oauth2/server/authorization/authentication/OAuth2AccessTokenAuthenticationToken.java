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
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Collections;

/**
 * @author Joe Grandja
 * @author Madhu Bhat
 */
public class OAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private RegisteredClient registeredClient;
	private Authentication clientPrincipal;
	private OAuth2AccessToken accessToken;

	public OAuth2AccessTokenAuthenticationToken(RegisteredClient registeredClient,
			Authentication clientPrincipal, OAuth2AccessToken accessToken) {
		super(Collections.emptyList());
		this.registeredClient = registeredClient;
		this.clientPrincipal = clientPrincipal;
		this.accessToken = accessToken;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return null;
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
