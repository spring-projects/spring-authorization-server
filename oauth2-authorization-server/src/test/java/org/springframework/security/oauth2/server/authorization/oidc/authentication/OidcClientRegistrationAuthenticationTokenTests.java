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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcClientRegistrationAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OidcClientRegistrationAuthenticationTokenTests {
	private TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
	private OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com").build();

	@Test
	public void constructorWhenPrincipalNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcClientRegistrationAuthenticationToken(null, this.clientRegistration))
				.withMessage("principal cannot be null");
	}

	@Test
	public void constructorWhenClientRegistrationNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcClientRegistrationAuthenticationToken(this.principal, null))
				.withMessage("clientRegistration cannot be null");
	}

	@Test
	public void constructorWhenAllValuesProvidedThenCreated() {
		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				this.principal, this.clientRegistration);

		assertThat(authentication.getPrincipal()).isEqualTo(this.principal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authentication.isAuthenticated()).isEqualTo(this.principal.isAuthenticated());
	}

}
