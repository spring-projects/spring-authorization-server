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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenIssuer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenMetadata;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenResult;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2RefreshTokenAuthenticationProvider}.
 *
 * @author Alexey Nesterov
 * @since 0.0.3
 */
public class OAuth2RefreshTokenAuthenticationProviderTests {

	private OAuth2AuthorizationService authorizationService;
	private OAuth2RefreshTokenAuthenticationProvider authenticationProvider;
	private OAuth2TokenIssuer<OAuth2AccessToken> mockAccessTokenIssuer;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.mockAccessTokenIssuer = mock(OAuth2TokenIssuer.class);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", issuedAt, expiresAt);
		OAuth2TokenMetadata accessTokenMetadata = OAuth2TokenMetadata.builder()
				.metadata(OAuth2TokenMetadata.TOKEN, mock(Jwt.class))
				.build();
		when(this.mockAccessTokenIssuer.issue(any())).thenReturn(OAuth2TokenResult.of(accessToken, accessTokenMetadata));

		this.authenticationProvider = new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService, this.mockAccessTokenIssuer);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(null, this.mockAccessTokenIssuer))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenAccessTokenIssuerNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("accessTokenIssuer cannot be null");
	}

	@Test
	public void supportsWhenSupportedAuthenticationThenTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2RefreshTokenAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedAuthenticationThenFalse() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class)).isFalse();
	}

	@Test
	public void authenticateWhenValidRefreshTokenThenReturnAccessToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId()).isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(updatedAuthorization.getTokens().getAccessToken());
		assertThat(updatedAuthorization.getTokens().getAccessToken()).isNotEqualTo(authorization.getTokens().getAccessToken());
		assertThat(accessTokenAuthentication.getRefreshToken()).isEqualTo(updatedAuthorization.getTokens().getRefreshToken());
		// By default, refresh token is reused
		assertThat(updatedAuthorization.getTokens().getRefreshToken()).isEqualTo(authorization.getTokens().getRefreshToken());
	}

	@Test
	public void authenticateWhenReuseRefreshTokensFalseThenReturnNewRefreshToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(tokenSettings -> tokenSettings.reuseRefreshTokens(false))
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRefreshToken()).isEqualTo(updatedAuthorization.getTokens().getRefreshToken());
		assertThat(updatedAuthorization.getTokens().getRefreshToken()).isNotEqualTo(authorization.getTokens().getRefreshToken());
	}

	@Test
	public void authenticateWhenRequestedScopesAuthorizedThenAccessTokenIncludesScopes() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
		Set<String> requestedScopes = new HashSet<>(authorizedScopes);
		requestedScopes.remove("email");
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal, requestedScopes);

		this.authenticationProvider.authenticate(authentication);

		verify(this.mockAccessTokenIssuer).issue(argThat(request -> request.getClaims().get("scope").equals(requestedScopes)));
	}

	@Test
	public void authenticateWhenRequestedScopesNotAuthorizedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
		Set<String> requestedScopes = new HashSet<>(authorizedScopes);
		requestedScopes.add("unauthorized");
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal, requestedScopes);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void authenticateWhenInvalidRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"invalid", clientPrincipal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"refresh-token", clientPrincipal);

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
				registeredClient.getClientId(), registeredClient.getClientSecret(), ClientAuthenticationMethod.BASIC, null);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"refresh-token", clientPrincipal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenRefreshTokenIssuedToAnotherClientThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				TestRegisteredClients.registeredClient2().build());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantTypes(grantTypes -> grantTypes.remove(AuthorizationGrantType.REFRESH_TOKEN))
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void authenticateWhenExpiredRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken expiredRefreshToken = new OAuth2RefreshToken2(
				"expired-refresh-token", Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));
		OAuth2Tokens tokens = OAuth2Tokens.from(authorization.getTokens()).refreshToken(expiredRefreshToken).build();
		authorization = OAuth2Authorization.from(authorization).tokens(tokens).build();
		when(this.authorizationService.findByToken(
				eq(authorization.getTokens().getRefreshToken().getTokenValue()),
				eq(TokenType.REFRESH_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getTokens().getRefreshToken().getTokenValue(), clientPrincipal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}
}
