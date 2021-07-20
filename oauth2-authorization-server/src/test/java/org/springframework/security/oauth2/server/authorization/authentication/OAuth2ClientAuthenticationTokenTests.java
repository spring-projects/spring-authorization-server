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

import org.junit.Test;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2ClientAuthenticationToken}.
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 */
public class OAuth2ClientAuthenticationTokenTests {

	@Test
	public void constructorWhenClientIdNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientAuthenticationToken(null, "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientId cannot be empty");
	}

	@Test
	public void constructorWhenClientSecretNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientAuthenticationToken("clientId", null, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientSecret cannot be empty");
	}

	@Test
	public void constructorWhenClientAuthenticationMethodNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientAuthenticationToken("clientId", "clientSecret", null, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientAuthenticationMethod cannot be null");
	}

	@Test
	public void constructorWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientAuthenticationToken(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClient cannot be null");
	}

	@Test
	public void constructorWhenClientCredentialsProvidedThenCreated() {
		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken("clientId", "secret",
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		assertThat(authentication.isAuthenticated()).isFalse();
		assertThat(authentication.getPrincipal().toString()).isEqualTo("clientId");
		assertThat(authentication.getCredentials()).isEqualTo("secret");
		assertThat(authentication.getRegisteredClient()).isNull();
		assertThat(authentication.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void constructorWhenClientIdProvidedThenCreated() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken("clientId", additionalParameters);
		assertThat(authentication.isAuthenticated()).isFalse();
		assertThat(authentication.getPrincipal().toString()).isEqualTo("clientId");
		assertThat(authentication.getCredentials()).isNull();
		assertThat(authentication.getAdditionalParameters()).isEqualTo(additionalParameters);
		assertThat(authentication.getRegisteredClient()).isNull();
		assertThat(authentication.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	@Test
	public void constructorWhenRegisteredClientProvidedThenCreated() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(registeredClient);
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getPrincipal().toString()).isEqualTo(registeredClient.getClientId());
		assertThat(authentication.getCredentials()).isNull();
		assertThat(authentication.getRegisteredClient()).isEqualTo(registeredClient);
	}
}
