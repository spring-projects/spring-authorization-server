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
package org.springframework.security.oauth2.server.authorization.client;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Resource containing the data of an {@link RegisteredClient} object.
 *
 * @author Steve Riesenberg
 * @since 0.2.2
 */
public class RegisteredClientResource {
	private String id;
	private String clientId;
	private Instant clientIdIssuedAt;
	private String clientSecret;
	private Instant clientSecretExpiresAt;
	private String clientName;
	private Set<String> clientAuthenticationMethods;
	private Set<String> authorizationGrantTypes;
	private Set<String> redirectUris;
	private Set<String> scopes;
	private Map<String, Object> clientSettings;
	private Map<String, Object> tokenSettings;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public Instant getClientIdIssuedAt() {
		return clientIdIssuedAt;
	}

	public void setClientIdIssuedAt(Instant clientIdIssuedAt) {
		this.clientIdIssuedAt = clientIdIssuedAt;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public Instant getClientSecretExpiresAt() {
		return clientSecretExpiresAt;
	}

	public void setClientSecretExpiresAt(Instant clientSecretExpiresAt) {
		this.clientSecretExpiresAt = clientSecretExpiresAt;
	}

	public String getClientName() {
		return clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public Set<String> getClientAuthenticationMethods() {
		return clientAuthenticationMethods;
	}

	public void setClientAuthenticationMethods(Set<String> clientAuthenticationMethods) {
		this.clientAuthenticationMethods = clientAuthenticationMethods;
	}

	public Set<String> getAuthorizationGrantTypes() {
		return authorizationGrantTypes;
	}

	public void setAuthorizationGrantTypes(Set<String> authorizationGrantTypes) {
		this.authorizationGrantTypes = authorizationGrantTypes;
	}

	public Set<String> getRedirectUris() {
		return redirectUris;
	}

	public void setRedirectUris(Set<String> redirectUris) {
		this.redirectUris = redirectUris;
	}

	public Set<String> getScopes() {
		return scopes;
	}

	public void setScopes(Set<String> scopes) {
		this.scopes = scopes;
	}

	public Map<String, Object> getClientSettings() {
		return clientSettings;
	}

	public void setClientSettings(Map<String, Object> clientSettings) {
		this.clientSettings = clientSettings;
	}

	public Map<String, Object> getTokenSettings() {
		return tokenSettings;
	}

	public void setTokenSettings(Map<String, Object> tokenSettings) {
		this.tokenSettings = tokenSettings;
	}
}
