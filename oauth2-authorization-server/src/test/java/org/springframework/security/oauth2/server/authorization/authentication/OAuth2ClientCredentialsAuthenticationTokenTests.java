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
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2ClientCredentialsAuthenticationToken}.
 *
 * @author Alexey Nesterov
 */
public class OAuth2ClientCredentialsAuthenticationTokenTests {
	private final OAuth2ClientAuthenticationToken clientPrincipal =
			new OAuth2ClientAuthenticationToken(TestRegisteredClients.registeredClient().build());

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientCredentialsAuthenticationToken(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenScopesNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientCredentialsAuthenticationToken(this.clientPrincipal, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("scopes cannot be null");
	}

	@Test
	public void constructorWhenClientPrincipalProvidedThenCreated() {
		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(this.clientPrincipal);

		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getScopes()).isEmpty();
	}

	@Test
	public void constructorWhenScopesProvidedThenCreated() {
		Set<String> expectedScopes = Collections.singleton("test-scope");

		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(this.clientPrincipal, expectedScopes);

		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getScopes()).isEqualTo(expectedScopes);
	}
}
