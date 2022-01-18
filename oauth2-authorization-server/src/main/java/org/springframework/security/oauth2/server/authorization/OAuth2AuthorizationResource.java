/*
 * Copyright 2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Resource containing the data of an {@link OAuth2Authorization} object.
 *
 * @author Steve Riesenberg
 * @since 0.2.2
 */
public class OAuth2AuthorizationResource {
	private String id;
	private String registeredClientId;
	private String principalName;
	private String authorizationGrantType;
	private String state;
	private Set<String> scopes;
	private Map<String, Object> attributes;
	private Map<String, OAuth2TokenResource> tokens;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getRegisteredClientId() {
		return registeredClientId;
	}

	public void setRegisteredClientId(String registeredClientId) {
		this.registeredClientId = registeredClientId;
	}

	public String getPrincipalName() {
		return principalName;
	}

	public void setPrincipalName(String principalName) {
		this.principalName = principalName;
	}

	public String getAuthorizationGrantType() {
		return authorizationGrantType;
	}

	public void setAuthorizationGrantType(String authorizationGrantType) {
		this.authorizationGrantType = authorizationGrantType;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public Set<String> getScopes() {
		return scopes;
	}

	public void setScopes(Set<String> scopes) {
		this.scopes = scopes;
	}

	public Map<String, Object> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, Object> attributes) {
		this.attributes = attributes;
	}

	public Map<String, OAuth2TokenResource> getTokens() {
		return tokens;
	}

	public void setTokens(Map<String, OAuth2TokenResource> tokens) {
		this.tokens = tokens;
	}

	public static class OAuth2TokenResource {
		private String tokenValue;
		private Instant issuedAt;
		private Instant expiresAt;
		private Map<String, Object> metadata;

		public String getTokenValue() {
			return tokenValue;
		}

		public void setTokenValue(String tokenValue) {
			this.tokenValue = tokenValue;
		}

		public Instant getIssuedAt() {
			return issuedAt;
		}

		public void setIssuedAt(Instant issuedAt) {
			this.issuedAt = issuedAt;
		}

		public Instant getExpiresAt() {
			return expiresAt;
		}

		public void setExpiresAt(Instant expiresAt) {
			this.expiresAt = expiresAt;
		}

		public Map<String, Object> getMetadata() {
			return metadata;
		}

		public void setMetadata(Map<String, Object> metadata) {
			this.metadata = metadata;
		}
	}
}
