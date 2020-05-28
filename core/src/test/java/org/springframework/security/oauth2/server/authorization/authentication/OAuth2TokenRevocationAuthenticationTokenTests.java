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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2TokenRevocationAuthenticationToken}.
 *
 * @author Vivek Babu
 */
public class OAuth2TokenRevocationAuthenticationTokenTests {
	private OAuth2TokenRevocationAuthenticationToken clientPrincipal = new OAuth2TokenRevocationAuthenticationToken(
			"Token", TestRegisteredClients.registeredClient().build(), null);
	private RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	@Test
	public void constructorWhenTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationAuthenticationToken(null,
				this.clientPrincipal, "hint"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be empty");
	}

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationAuthenticationToken("token",
				(Authentication) null, "hint"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenTokenNullRegisteredClientPresentThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationAuthenticationToken(null, registeredClient, "hint"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be empty");
	}

	@Test
	public void constructorWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationAuthenticationToken("token",
				(RegisteredClient) null, "hint"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClient cannot be null");
	}

	@Test
	public void constructorWhenTokenAndClientPrincipalProvidedThenCreated() {
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", this.clientPrincipal, "token_hint");
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getToken()).isEqualTo("token");
		assertThat(authentication.getTokenTypeHint()).isEqualTo("token_hint");
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void constructorWhenTokenAndRegisteredProvidedThenCreated() {
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", this.registeredClient, "token_hint");
		assertThat(authentication.getPrincipal()).isEqualTo(this.registeredClient.getClientId());
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getToken()).isEqualTo("token");
		assertThat(authentication.getTokenTypeHint()).isEqualTo("token_hint");
		assertThat(authentication.isAuthenticated()).isTrue();
	}
}
