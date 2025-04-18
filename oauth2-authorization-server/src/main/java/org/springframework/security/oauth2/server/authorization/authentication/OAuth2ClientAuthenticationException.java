/*
 * Copyright 2020-2025 the original author or authors.
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

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationException} that holds an
 * {@link OAuth2ClientAuthenticationToken} and is used by an
 * {@code AuthenticationFailureHandler} when handling a failed authentication attempt by
 * an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @since 1.5
 * @see OAuth2ClientAuthenticationToken
 */
public class OAuth2ClientAuthenticationException extends OAuth2AuthenticationException {

	private final OAuth2ClientAuthenticationToken clientAuthentication;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationException} using the provided
	 * parameters.
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param clientAuthentication the {@link OAuth2ClientAuthenticationToken OAuth 2.0
	 * Client Authentication} request
	 */
	public OAuth2ClientAuthenticationException(OAuth2Error error,
			OAuth2ClientAuthenticationToken clientAuthentication) {
		super(error);
		Assert.notNull(clientAuthentication, "clientAuthentication cannot be null");
		this.clientAuthentication = clientAuthentication;
	}

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationException} using the provided
	 * parameters.
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param cause the root cause
	 * @param clientAuthentication the {@link OAuth2ClientAuthenticationToken OAuth 2.0
	 * Client Authentication} request
	 */
	public OAuth2ClientAuthenticationException(OAuth2Error error, Throwable cause,
			OAuth2ClientAuthenticationToken clientAuthentication) {
		super(error, cause);
		Assert.notNull(clientAuthentication, "clientAuthentication cannot be null");
		this.clientAuthentication = clientAuthentication;
	}

	/**
	 * Returns the {@link OAuth2ClientAuthenticationToken OAuth 2.0 Client Authentication}
	 * request.
	 * @return the {@link OAuth2ClientAuthenticationToken}
	 */
	public OAuth2ClientAuthenticationToken getClientAuthentication() {
		return this.clientAuthentication;
	}

}
