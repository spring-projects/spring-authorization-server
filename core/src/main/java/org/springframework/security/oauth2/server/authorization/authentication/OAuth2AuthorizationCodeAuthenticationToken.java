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

import java.util.Collections;

/**
 * @author Joe Grandja
 * @author Madhu Bhat
 */
public class OAuth2AuthorizationCodeAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private String code;
	private Authentication clientPrincipal;
	private String clientId;
	private String redirectUri;

	public OAuth2AuthorizationCodeAuthenticationToken(String code,
			Authentication clientPrincipal, @Nullable String redirectUri) {
		super(Collections.emptyList());
		this.code = code;
		this.clientPrincipal = clientPrincipal;
		this.redirectUri = redirectUri;
	}

	public OAuth2AuthorizationCodeAuthenticationToken(String code,
			String clientId, @Nullable String redirectUri) {
		super(Collections.emptyList());
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
	 * Returns the code.
	 *
	 * @return the code
	 */
	public String getCode() {
		return this.code;
	}

	/**
	 * Returns the redirectUri.
	 *
	 * @return the redirectUri
	 */
	public String getRedirectUri() {
		return this.redirectUri;
	}
}
