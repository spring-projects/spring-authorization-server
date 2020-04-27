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
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import java.util.Collections;

/**
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 */
public class OAuth2ClientAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private String clientId;
	private String clientSecret;
	private RegisteredClient registeredClient;

	public OAuth2ClientAuthenticationToken(String clientId, String clientSecret) {
		super(Collections.emptyList());
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	public OAuth2ClientAuthenticationToken(RegisteredClient registeredClient) {
		super(Collections.emptyList());
		this.registeredClient = registeredClient;
		setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return this.clientSecret;
	}

	@Override
	public Object getPrincipal() {
		return this.clientId;
	}
}
