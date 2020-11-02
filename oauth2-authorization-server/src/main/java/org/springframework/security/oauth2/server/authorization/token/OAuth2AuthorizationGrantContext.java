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

package org.springframework.security.oauth2.server.authorization.token;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * Context describing current status of OAuth2 authorization. User by a {@link OAuth2TokenIssuer} to issue a new OAuth2 token.
 *
 * Different implementations of {@link OAuth2TokenIssuer} may decide to use different properties of
 * the context.
 *
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class OAuth2AuthorizationGrantContext {

	private final String principalName;
	private final RegisteredClient registeredClient;
	private final Map<String, Object> claims;

	private OAuth2AuthorizationGrantContext(String principalName, RegisteredClient registeredClient, Map<String, Object> claims) {
		this.principalName = principalName;
		this.registeredClient = registeredClient;
		this.claims = claims;
	}

	/**
	 * Registered client associated with the request. Usually that would be the current authenticated client.
	 * @return a registered client
	 */
	public RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}

	/**
	 * Resource owner's principal name.
	 * @return a principal representing resource owner
	 */
	public String getPrincipalName() {
		return this.principalName;
	}

	/**
	 * Requested claims. Token issuer may decide to ignore or change requested claims completely.
	 * @return requested claims
	 */
	public Map<String, Object> getClaims() {
		return claims;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		private RegisteredClient registeredClient;
		private String principalName;
		private final Map<String, Object> claims = new HashMap<>();

		private Builder() {

		}

		/**
		 * Set registered client associated with the request. Usually that would be the current authenticated client.
		 * @param client current authenticated client
		 */
		public Builder registeredClient(RegisteredClient client) {
			this.registeredClient = client;
			return this;
		}

		/**
		 * Set resource owner's principal name.
		 * @param principalName name of the principal representing resource owner
		 */
		public Builder principalName(String principalName) {
			this.principalName = principalName;
			return this;
		}

		/**
		 * Set requested claims. Token issuer may decide to ignore or change requested claims completely.
		 * @param claims requested claims
		 */
		public Builder claims(Map<String, Object> claims) {
			this.claims.putAll(claims);
			return this;
		}

		/**
		 * Add a new requested claim. Token issuer may decide to ignore or change requested claims completely.
		 * @param name name of the claim to add
		 * @param value value of the claim to add
		 */
		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Build a token request
		 * @return a new token request
		 */
		public OAuth2AuthorizationGrantContext build() {
			Assert.notNull(this.principalName, "principalName cannot be null");
			Assert.notNull(this.registeredClient, "registeredClient cannot be null");

			return new OAuth2AuthorizationGrantContext(this.principalName, this.registeredClient, this.claims);
		}
	}
}
