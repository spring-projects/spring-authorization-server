/*
 * Copyright 2020-2023 the original author or authors.
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

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * @author Anoop Garlapati
 */
public class TestRegisteredClients {
	public static final String SCOPE_1 = "scope1";
	public static final String SCOPE_2 = "scope2";

	public static RegisteredClient.Builder registeredClient() {
		return RegisteredClient.withId("registration-1")
				.clientId("client-1")
				.clientIdIssuedAt(Instant.now().truncatedTo(ChronoUnit.SECONDS))
				.clientSecret("secret-1")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.redirectUri("https://example.com/callback-1")
				.redirectUri("https://example.com/callback-2")
				.redirectUri("https://example.com/callback-3")
				.postLogoutRedirectUri("https://example.com/oidc-post-logout")
				.scope(SCOPE_1);
	}

	public static RegisteredClient.Builder registeredClient2() {
		return RegisteredClient.withId("registration-2")
				.clientId("client-2")
				.clientIdIssuedAt(Instant.now().truncatedTo(ChronoUnit.SECONDS))
				.clientSecret("secret-2")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.redirectUri("https://example.com")
				.postLogoutRedirectUri("https://example.com/oidc-post-logout")
				.scope(SCOPE_1)
				.scope(SCOPE_2);
	}

	public static RegisteredClient.Builder registeredPublicClient() {
		return RegisteredClient.withId("registration-3")
				.clientId("client-3")
				.clientIdIssuedAt(Instant.now().truncatedTo(ChronoUnit.SECONDS))
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.redirectUri("https://example.com")
				.scope(SCOPE_1)
				.clientSettings(ClientSettings.builder().requireProofKey(true).build());
	}
}
