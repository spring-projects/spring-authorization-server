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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Password Grant.
 *
 * @author leegecho
 * @since 0.1.2
 * @see OAuth2UsernamePasswordAuthenticationToken
 * @see OAuth2UsernamePasswordAuthenticationProvider
 */
public class OAuth2UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String username;

	private final String password;

	private final AuthorizationGrantType authorizationGrantType;
	private final Authentication clientPrincipal;
	private final Map<String, Object> additionalParameters;

	public OAuth2UsernamePasswordAuthenticationToken(Authentication clientPrincipal, String username, String password, Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		this.clientPrincipal = clientPrincipal;
		this.username = username;
		this.password = password;
		this.authorizationGrantType = AuthorizationGrantType.PASSWORD;
		this.additionalParameters = additionalParameters;
		setAuthenticated(false);
	}

	public OAuth2UsernamePasswordAuthenticationToken(Authentication clientPrincipal, String username, String password, Map<String, Object> additionalParameters, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.username = username;
		this.password = password;
		this.authorizationGrantType = AuthorizationGrantType.PASSWORD;
		this.clientPrincipal = clientPrincipal;
		this.additionalParameters = additionalParameters;
		super.setAuthenticated(true);
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public AuthorizationGrantType getAuthorizationGrantType() {
		return authorizationGrantType;
	}

	public Authentication getClientPrincipal() {
		return clientPrincipal;
	}

	public Map<String, Object> getAdditionalParameters() {
		return additionalParameters;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public Object getPrincipal() {
		return clientPrincipal;
	}
}
