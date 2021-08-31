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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.Version;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for OpenID Connect Dynamic Client Registration 1.0.
 *
 * @author Joe Grandja
 * @author Ovidiu Popa
 * @since 0.1.1
 * @see AbstractAuthenticationToken
 * @see OidcClientRegistration
 * @see OidcClientRegistrationAuthenticationProvider
 */
public class OidcClientRegistrationAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final Authentication principal;
	private OidcClientRegistration clientRegistration;
	private String clientId;
	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationToken} using the provided parameters.
	 *
	 * @param principal the authenticated principal
	 * @param clientRegistration the client registration
	 */
	public OidcClientRegistrationAuthenticationToken(Authentication principal, OidcClientRegistration clientRegistration) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		this.principal = principal;
		this.clientRegistration = clientRegistration;
		setAuthenticated(principal.isAuthenticated());
	}

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationToken} using the provided parameters.
	 *
	 * @param principal the authenticated principal
	 * @param clientId the registered client_id
	 */
	public OidcClientRegistrationAuthenticationToken(Authentication principal, String clientId) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(clientId, "clientId cannot be null or empty");
		this.principal = principal;
		this.clientId = clientId;
		setAuthenticated(principal.isAuthenticated());
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the client registration.
	 *
	 * @return the client registration
	 */
	public OidcClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	/**
	 * Returns the registered client_id.
	 *
	 * @return the registered client_id
	 * @since 0.2.1
	 */
	public String getClientId() {
		return this.clientId;
	}

}
