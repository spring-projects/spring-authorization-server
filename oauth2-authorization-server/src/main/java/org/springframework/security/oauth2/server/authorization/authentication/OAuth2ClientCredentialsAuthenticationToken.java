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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Client Credentials Grant.
 *
 * @author Alexey Nesterov
 * @since 0.0.1
 * @see OAuth2AuthorizationGrantAuthenticationToken
 * @see OAuth2ClientCredentialsAuthenticationProvider
 */
public class OAuth2ClientCredentialsAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationToken} using the provided parameters.
	 *
	 * @param clientPrincipal the authenticated client principal
	 */
	public OAuth2ClientCredentialsAuthenticationToken(Authentication clientPrincipal) {
		this(clientPrincipal, Collections.emptySet());
	}

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationToken} using the provided parameters.
	 *
	 * @param clientPrincipal the authenticated client principal
	 * @param scopes the requested scope(s)
	 */
	public OAuth2ClientCredentialsAuthenticationToken(Authentication clientPrincipal, Set<String> scopes) {
		super(AuthorizationGrantType.CLIENT_CREDENTIALS, clientPrincipal, null);
		Assert.notNull(scopes, "scopes cannot be null");
		this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
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
