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
package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * @author Anoop Garlapati
 */
public class TestRegisteredClients {

	public static RegisteredClient.Builder registeredClient() {
		return RegisteredClient.withId("registration-1")
				.clientId("client-1")
				.clientSecret("secret")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("https://example.com")
				.scope("openid")
				.scope("profile")
				.scope("email");
	}

	public static RegisteredClient.Builder registeredClient2() {
		return RegisteredClient.withId("registration-2")
				.clientId("client-2")
				.clientSecret("secret")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("https://example.com")
				.scope("openid")
				.scope("profile")
				.scope("email")
				.scope("scope1")
				.scope("scope2");
	}

	public static RegisteredClient.Builder registeredPublicClient() {
		return RegisteredClient.withId("registration-3")
				.clientId("client-3")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.redirectUri("https://example.com")
				.scope("openid")
				.scope("profile")
				.scope("email")
				.clientSettings(clientSettings -> clientSettings.requireProofKey(true));
	}
}
