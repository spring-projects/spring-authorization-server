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
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @since 0.0.1
 * @see AbstractAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 */
public class OAuth2AuthorizationCodeAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private String code;
	private Authentication clientPrincipal;
	private String clientId;
	private String redirectUri;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
	 *
	 * @param code the authorization code
	 * @param clientPrincipal the authenticated client principal
	 * @param redirectUri the redirect uri
	 */
	public OAuth2AuthorizationCodeAuthenticationToken(String code,
			Authentication clientPrincipal, @Nullable String redirectUri) {
		super(Collections.emptyList());
		Assert.hasText(code, "code cannot be empty");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.code = code;
		this.clientPrincipal = clientPrincipal;
		this.redirectUri = redirectUri;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
	 *
	 * @param code the authorization code
	 * @param clientId the client identifier
	 * @param redirectUri the redirect uri
	 */
	public OAuth2AuthorizationCodeAuthenticationToken(String code,
			String clientId, @Nullable String redirectUri) {
		super(Collections.emptyList());
		Assert.hasText(code, "code cannot be empty");
		Assert.hasText(clientId, "clientId cannot be empty");
		this.code = code;
		this.clientId = clientId;
		this.redirectUri = redirectUri;
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal != null ? this.clientPrincipal : this.clientId;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the authorization code.
	 *
	 * @return the authorization code
	 */
	public String getCode() {
		return this.code;
	}

	/**
	 * Returns the redirect uri.
	 *
	 * @return the redirect uri
	 */
	public @Nullable String getRedirectUri() {
		return this.redirectUri;
	}
}
