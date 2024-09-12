/*
 * Copyright 2020-2024 the original author or authors.
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
package sample.redis.entity;

import java.security.Principal;
import java.time.Instant;
import java.util.Set;

import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class OAuth2AuthorizationCodeGrantAuthorization extends OAuth2AuthorizationGrantAuthorization {

	private final Principal principal;

	private final OAuth2AuthorizationRequest authorizationRequest;

	private final AuthorizationCode authorizationCode;

	@Indexed
	private final String state; // Used to correlate the request during the authorization
								// consent flow

	// @fold:on
	public OAuth2AuthorizationCodeGrantAuthorization(String id, String registeredClientId, String principalName,
			Set<String> authorizedScopes, AccessToken accessToken, RefreshToken refreshToken, Principal principal,
			OAuth2AuthorizationRequest authorizationRequest, AuthorizationCode authorizationCode, String state) {
		super(id, registeredClientId, principalName, authorizedScopes, accessToken, refreshToken);
		this.principal = principal;
		this.authorizationRequest = authorizationRequest;
		this.authorizationCode = authorizationCode;
		this.state = state;
	}

	public Principal getPrincipal() {
		return this.principal;
	}

	public OAuth2AuthorizationRequest getAuthorizationRequest() {
		return this.authorizationRequest;
	}

	public AuthorizationCode getAuthorizationCode() {
		return this.authorizationCode;
	}

	public String getState() {
		return this.state;
	}

	public static class AuthorizationCode extends AbstractToken {

		public AuthorizationCode(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
			super(tokenValue, issuedAt, expiresAt, invalidated);
		}

	}
	// @fold:off

}
