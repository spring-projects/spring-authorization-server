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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import java.util.Collections;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2ClientAuthenticationProvider}.
 *
 * @author Patryk Kostrzewa
 */
public class OAuth2ClientAuthenticationProviderTests {

	private RegisteredClient registeredClient;
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2ClientAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.registeredClient = TestRegisteredClients.registeredClient()
				.build();
		this.registeredClientRepository = new InMemoryRegisteredClientRepository(this.registeredClient);
		this.authenticationProvider = new OAuth2ClientAuthenticationProvider(this.registeredClientRepository);
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientAuthenticationProvider(null)).isInstanceOf(
				IllegalArgumentException.class);
	}

	@Test
	public void supportsWhenTypeOAuth2ClientAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenNullCredentialsThenThrowOAuth2AuthorizationException() {
		assertThatThrownBy(() -> {
			this.authenticationProvider.authenticate(new OAuth2ClientAuthenticationToken("id", null));
		}).isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticateWhenNullRegisteredClientThenThrowOAuth2AuthorizationException() {
		assertThatThrownBy(() -> {
			this.authenticationProvider.authenticate(new OAuth2ClientAuthenticationToken("id", "secret"));
		}).isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticateWhenCredentialsNotEqualThenThrowOAuth2AuthorizationException() {
		assertThatThrownBy(() -> {
			this.authenticationProvider.authenticate(
					new OAuth2ClientAuthenticationToken(this.registeredClient.getClientId(),
							this.registeredClient.getClientSecret() + "_invalid"));
		}).isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticateWhenAuthenticationSuccessResponseThenReturnClientAuthenticationToken() {
		OAuth2ClientAuthenticationToken authenticationResult = (OAuth2ClientAuthenticationToken) this.authenticationProvider.authenticate(
				new OAuth2ClientAuthenticationToken(this.registeredClient.getClientId(),
						registeredClient.getClientSecret()));
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getAuthorities()).isEqualTo(Collections.emptyList());
	}
}
