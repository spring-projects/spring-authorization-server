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
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("https://example.com")
				.scope("openid")
				.scope("profile")
				.scope("email");
	}

	public static RegisteredClient.Builder validAuthorizationGrantRegisteredClient() {
		return RegisteredClient.withId("valid_client_id")
				.clientId("valid_client")
				.clientSecret("valid_secret")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("http://localhost:8080/test-application/callback")
				.scope("openid")
				.scope("profile")
				.scope("email");
	}

	public static RegisteredClient.Builder validAuthorizationGrantClientMultiRedirectUris() {
		return RegisteredClient.withId("valid_client_multi_uri_id")
				.clientId("valid_client_multi_uri")
				.clientSecret("valid_secret")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("http://localhost:8080/test-application/callback")
				.redirectUri("http://localhost:8080/another-test-application/callback")
				.scope("openid")
				.scope("profile")
				.scope("email");
	}

	public static RegisteredClient.Builder validClientCredentialsGrantRegisteredClient() {
		return RegisteredClient.withId("valid_cc_client_id")
				.clientId("valid_cc_client")
				.clientSecret("valid_secret")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.scope("openid")
				.scope("profile")
				.scope("email");
	}
}
