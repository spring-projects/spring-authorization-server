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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenRevocationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2TokenRevocationAuthenticationProvider}.
 *
 * @author Vivek Babu
 */
public class OAuth2TokenRevocationAuthenticationProviderTests {
	private RegisteredClient registeredClient;
	private OAuth2AuthorizationService oAuth2AuthorizationService;
	private OAuth2TokenRevocationService oAuth2TokenRevocationService;
	private OAuth2TokenRevocationAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.registeredClient = TestRegisteredClients.registeredClient().build();
		this.oAuth2AuthorizationService = mock(OAuth2AuthorizationService.class);
		this.oAuth2TokenRevocationService = mock(OAuth2TokenRevocationService.class);
		this.authenticationProvider = new OAuth2TokenRevocationAuthenticationProvider(oAuth2AuthorizationService,
				oAuth2TokenRevocationService);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationAuthenticationProvider(null,
				oAuth2TokenRevocationService))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenRevocationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationAuthenticationProvider(oAuth2AuthorizationService,
				null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenRevocationService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2TokenRevocationAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2TokenRevocationAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				this.registeredClient.getClientId(), this.registeredClient.getClientSecret());
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, "access_token");
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				this.registeredClient.getClientId(), this.registeredClient.getClientSecret());
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, "access_token");
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidTokenThenAuthenticate() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, "access_token");
		OAuth2TokenRevocationAuthenticationToken authenticationResult =
				(OAuth2TokenRevocationAuthenticationToken) this.authenticationProvider.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getPrincipal().toString()).isEqualTo(this.registeredClient.getClientId());
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(this.registeredClient);
	}

	@Test
	public void authenticateWhenAuthorizationIssuedToAnotherClientThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		when(this.oAuth2AuthorizationService.findByTokenAndTokenType(eq("token"), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				TestRegisteredClients.registeredClient2().build());
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, "access_token");
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenValidAccessTokenThenInvalidateTokenAndAuthenticate() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, "access_token");
		OAuth2Authorization mockAuthorization = mock(OAuth2Authorization.class);
		when(oAuth2AuthorizationService.findByTokenAndTokenType(eq("token"), eq(TokenType.ACCESS_TOKEN))).
				thenReturn(mockAuthorization);
		when(mockAuthorization.getRegisteredClientId()).thenReturn(this.registeredClient.getClientId());
		OAuth2TokenRevocationAuthenticationToken authenticationResult =
				(OAuth2TokenRevocationAuthenticationToken) this.authenticationProvider.authenticate(authentication);
		verify(this.oAuth2TokenRevocationService).revoke(eq("token"), eq(TokenType.ACCESS_TOKEN));

		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.getPrincipal().toString()).isEqualTo(this.registeredClient.getClientId());
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(this.registeredClient);
	}
}
