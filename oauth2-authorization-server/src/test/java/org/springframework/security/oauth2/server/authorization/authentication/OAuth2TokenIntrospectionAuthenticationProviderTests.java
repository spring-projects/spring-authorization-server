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

import static java.time.Duration.ofHours;
import static java.time.Instant.now;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor.ACTIVE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.USERNAME;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

/**
 * Tests for {@link OAuth2TokenIntrospectionAuthenticationProvider}.
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionAuthenticationProviderTests {
	private OAuth2AuthorizationService authorizationService;
	private OAuth2TokenIntrospectionAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authenticationProvider = new OAuth2TokenIntrospectionAuthenticationProvider(this.authorizationService);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionAuthenticationProvider(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authorizationService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2TokenIntrospectionAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2TokenIntrospectionAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret());
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue());
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret(), ClientAuthenticationMethod.BASIC,
				null);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue());
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidOAuth2TokenTypeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, "unsupportedOAuth2TokenType");
		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
	}

	@Test
	public void authenticateWhenTokenNotFoundThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue());
		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
	}

	@Test
	public void authenticateWhenInvalidatedTokenThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, accessToken);
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), isNull()))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
	}

	@Test
	public void authenticateWhenValidAccessTokenThenActiveWithScopes() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now(), Instant.now().plusSeconds(300),
				new HashSet<>(Arrays.asList("scope1", "Scope2")));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.accessToken(accessToken).build();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), isNull()))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isTrue();
		assertThat(authenticationResult.getClaims()).containsEntry(ACTIVE, true)
				.containsEntry(IAT, accessToken.getIssuedAt()).containsEntry(EXP, accessToken.getExpiresAt())
				.containsEntry(TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER).containsEntry(CLIENT_ID, "client-1")
				.containsEntry(USERNAME, "principal").containsKey(SCOPE)
				.containsAllEntriesOf(authorization.getAccessToken().getClaims());

	}

	@Test
	public void authenticateWhenValidRefreshTokenThenActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
		when(this.authorizationService.findByToken(eq(refreshToken.getTokenValue()), isNull()))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				refreshToken.getTokenValue(), clientPrincipal, OAuth2TokenType.REFRESH_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isTrue();
		assertThat(authenticationResult.getClaims()).containsEntry(ACTIVE, true)
				.containsEntry(IAT, refreshToken.getIssuedAt()).containsEntry(EXP, refreshToken.getExpiresAt())
				.containsEntry(USERNAME, "principal").containsEntry(CLIENT_ID, "client-1").hasSize(5);
	}

	@Test
	public void authenticateWhenExpiredTokenThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Instant expiresAt = Instant.now().minus(ofHours(1));
		Instant issuedAt = expiresAt.minus(ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "access-token", issuedAt, expiresAt);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).token(accessToken)
				.build();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), isNull()))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
		assertThat(authenticationResult.getClaims()).isNull();
	}

	@Test
	public void authenticateWhenInvalidNotBeforeClaimThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "access-token", issuedAt, expiresAt);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(
						accessToken,
						(metadata) -> metadata.put(
								OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
								Collections.singletonMap(JwtClaimNames.NBF, now().plus(ofHours(1)))))
				.build();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), isNull()))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
		assertThat(authenticationResult.getClaims()).isNull();
	}
}
