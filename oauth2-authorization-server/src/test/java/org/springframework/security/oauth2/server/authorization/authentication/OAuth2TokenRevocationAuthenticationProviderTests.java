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
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2TokenRevocationAuthenticationProvider}.
 *
 * @author Vivek Babu
 * @author Joe Grandja
 */
public class OAuth2TokenRevocationAuthenticationProviderTests {
	private OAuth2AuthorizationService authorizationService;
	private OAuth2TokenRevocationAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authenticationProvider = new OAuth2TokenRevocationAuthenticationProvider(this.authorizationService);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationAuthenticationProvider(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2TokenRevocationAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2TokenRevocationAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret());
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret(), null);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidTokenTypeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, "unsupported_token_type");
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo("unsupported_token_type");
	}

	@Test
	public void authenticateWhenInvalidTokenThenNotRevoked() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());
		OAuth2TokenRevocationAuthenticationToken authenticationResult =
				(OAuth2TokenRevocationAuthenticationToken) this.authenticationProvider.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isFalse();
		verify(this.authorizationService, never()).save(any());
	}

	@Test
	public void authenticateWhenTokenIssuedToAnotherClientThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				TestRegisteredClients.registeredClient2().build()).build();
		when(this.authorizationService.findByToken(
				eq("token"),
				eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenValidRefreshTokenThenRevoked() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal, TokenType.REFRESH_TOKEN.getValue());

		OAuth2TokenRevocationAuthenticationToken authenticationResult =
				(OAuth2TokenRevocationAuthenticationToken) this.authenticationProvider.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		OAuth2RefreshToken refreshToken = updatedAuthorization.getTokens().getRefreshToken();
		assertThat(updatedAuthorization.getTokens().getTokenMetadata(refreshToken).isInvalidated()).isTrue();
		OAuth2AccessToken accessToken = updatedAuthorization.getTokens().getAccessToken();
		assertThat(updatedAuthorization.getTokens().getTokenMetadata(accessToken).isInvalidated()).isTrue();
	}

	@Test
	public void authenticateWhenValidAccessTokenThenRevoked() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getAccessToken().getTokenValue()),
				eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenRevocationAuthenticationToken authentication = new OAuth2TokenRevocationAuthenticationToken(
				authorization.getTokens().getAccessToken().getTokenValue(), clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenRevocationAuthenticationToken authenticationResult =
				(OAuth2TokenRevocationAuthenticationToken) this.authenticationProvider.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		OAuth2AccessToken accessToken = updatedAuthorization.getTokens().getAccessToken();
		assertThat(updatedAuthorization.getTokens().getTokenMetadata(accessToken).isInvalidated()).isTrue();
		OAuth2RefreshToken refreshToken = updatedAuthorization.getTokens().getRefreshToken();
		assertThat(updatedAuthorization.getTokens().getTokenMetadata(refreshToken).isInvalidated()).isFalse();
	}
}
