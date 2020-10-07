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

import java.util.Collections;
import java.util.Set;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Refresh Token Grant.
 *
 * @author Alexey Nesterov
 * @since 0.0.3
 * @see AbstractAuthenticationToken
 * @see OAuth2RefreshTokenAuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 */
public class OAuth2RefreshTokenAuthenticationToken extends AbstractAuthenticationToken {

	private final Authentication clientPrincipal;
	private final String refreshToken;
	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2RefreshTokenAuthenticationToken} using the provided parameters.
	 *
	 * @param refreshToken refresh token value
	 * @param clientPrincipal the authenticated client principal
	 */
	public OAuth2RefreshTokenAuthenticationToken(String refreshToken, Authentication clientPrincipal) {
		this(clientPrincipal, refreshToken, Collections.emptySet());
	}

	/**
	 * Constructs an {@code OAuth2RefreshTokenAuthenticationToken} using the provided parameters.
	 *
	 * @param clientPrincipal the authenticated client principal
	 * @param refreshToken refresh token value
	 * @param requestedScopes scopes requested by refresh token
	 */
	public OAuth2RefreshTokenAuthenticationToken(Authentication clientPrincipal, String refreshToken, Set<String> requestedScopes) {
		super(Collections.emptySet());

		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.hasText(refreshToken, "refreshToken cannot be null or empty");

		this.clientPrincipal = clientPrincipal;
		this.refreshToken = refreshToken;
		this.scopes = requestedScopes;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	public String getRefreshToken() {
		return this.refreshToken;
	}

	/**
	 * Returns the requested scope(s).
	 *
	 * @return the requested scope(s), or an empty {@code Set} if not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}
}
