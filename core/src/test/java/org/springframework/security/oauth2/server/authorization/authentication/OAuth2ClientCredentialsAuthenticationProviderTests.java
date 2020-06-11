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

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Alexey Nesterov
 */
public class OAuth2ClientCredentialsAuthenticationProviderTests {

	private static final RegisteredClient EXISTING_CLIENT = TestRegisteredClients.registeredClient().build();
	private OAuth2ClientCredentialsAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.authenticationProvider = new OAuth2ClientCredentialsAuthenticationProvider();
	}

	@Test
	public void supportsWhenSupportedClassThenTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedClassThenFalse() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationProvider.class)).isFalse();
	}

	@Test
	public void authenticateWhenValidAuthenticationThenReturnTokenWithClient() {
		Authentication authentication = this.authenticationProvider.authenticate(getAuthentication());
		assertThat(authentication).isInstanceOf(OAuth2AccessTokenAuthenticationToken.class);

		OAuth2AccessTokenAuthenticationToken token = (OAuth2AccessTokenAuthenticationToken) authentication;
		assertThat(token.getRegisteredClient()).isEqualTo(EXISTING_CLIENT);
	}

	@Test
	public void authenticateWhenValidAuthenticationThenGenerateTokenValue() {
		Authentication authentication = this.authenticationProvider.authenticate(getAuthentication());
		OAuth2AccessTokenAuthenticationToken token = (OAuth2AccessTokenAuthenticationToken) authentication;
		assertThat(token.getAccessToken().getTokenValue()).isNotBlank();
	}

	@Test
	public void authenticateWhenValidateScopeThenReturnTokenWithScopes() {
		Authentication authentication = this.authenticationProvider.authenticate(getAuthentication());
		OAuth2AccessTokenAuthenticationToken token = (OAuth2AccessTokenAuthenticationToken) authentication;
		assertThat(token.getAccessToken().getScopes()).containsAll(EXISTING_CLIENT.getScopes());
	}

	@Test
	public void authenticateWhenNoScopeRequestedThenUseDefaultScopes() {
		OAuth2ClientCredentialsAuthenticationToken authenticationToken = new OAuth2ClientCredentialsAuthenticationToken(new OAuth2ClientAuthenticationToken(EXISTING_CLIENT));
		Authentication authentication = this.authenticationProvider.authenticate(authenticationToken);
		OAuth2AccessTokenAuthenticationToken token = (OAuth2AccessTokenAuthenticationToken) authentication;
		assertThat(token.getAccessToken().getScopes()).containsAll(EXISTING_CLIENT.getScopes());
	}

	@Test
	public void authenticateWhenInvalidSecretThenThrowException() {
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				new OAuth2ClientAuthenticationToken(EXISTING_CLIENT.getClientId(), "not-a-valid-secret"));

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticateWhenNonExistingClientThenThrowException() {
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				new OAuth2ClientAuthenticationToken("another-client-id", "another-secret"));

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void authenticateWhenInvalidScopesThenThrowException() {
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				new OAuth2ClientAuthenticationToken(EXISTING_CLIENT), Collections.singleton("non-existing-scope"));

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	private OAuth2ClientCredentialsAuthenticationToken getAuthentication() {
		return new OAuth2ClientCredentialsAuthenticationToken(new OAuth2ClientAuthenticationToken(EXISTING_CLIENT), EXISTING_CLIENT.getScopes());
	}
}
