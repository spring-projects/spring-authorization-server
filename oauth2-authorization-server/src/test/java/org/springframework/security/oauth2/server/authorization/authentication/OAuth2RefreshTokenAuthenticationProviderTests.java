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

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jose.JoseHeaderNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Alexey Nesterov
 * @since 0.0.3
 */
public class OAuth2RefreshTokenAuthenticationProviderTests {

	private final String NEW_ACCESS_TOKEN_VALUE = UUID.randomUUID().toString();
	private final String REFRESH_TOKEN_VALUE = UUID.randomUUID().toString();

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
	private final OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);

	private final OAuth2AccessToken existingAccessToken = new OAuth2AccessToken(
			OAuth2AccessToken.TokenType.BEARER,
			"old-test-access-token",
			Instant.now(),
			Instant.now().plusSeconds(10),
			this.registeredClient.getScopes());

	private final OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient)
															.tokens(OAuth2Tokens.builder()
																			.accessToken(this.existingAccessToken)
																			.refreshToken(new OAuth2RefreshToken(REFRESH_TOKEN_VALUE, Instant.now(), Instant.now().plusSeconds(60)))
																			.build())
															.build();

	private OAuth2AuthorizationService authorizationService;
	private JwtEncoder jwtEncoder;
	private OAuth2RefreshTokenAuthenticationProvider provider;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		this.provider = new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService, this.jwtEncoder);

		Jwt jwt = Jwt.withTokenValue(NEW_ACCESS_TOKEN_VALUE)
						.issuedAt(Instant.now())
						.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
						.build();

		when(this.jwtEncoder.encode(any(), any())).thenReturn(jwt);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(null, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenJwtEncoderNullThenThrowException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("jwtEncoder cannot be null");
	}

	@Test
	public void supportsWhenSupportedAuthenticationThenTrue() {
		assertThat(this.provider.supports(OAuth2RefreshTokenAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedAuthenticationThenFalse() {
		assertThat(this.provider.supports(OAuth2ClientCredentialsAuthenticationToken.class)).isFalse();
	}

	@Test
	public void authenticateWhenRefreshTokenExistsThenReturnAuthentication() {
		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(this.authorization);

		OAuth2RefreshTokenAuthenticationToken token = new OAuth2RefreshTokenAuthenticationToken(REFRESH_TOKEN_VALUE, this.clientPrincipal);
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.provider.authenticate(token);

		ArgumentCaptor<JwtClaimsSet> claimsSetArgumentCaptor = ArgumentCaptor.forClass(JwtClaimsSet.class);
		verify(this.jwtEncoder).encode(any(), claimsSetArgumentCaptor.capture());

		assertThat(claimsSetArgumentCaptor.getValue().getSubject()).isEqualTo(this.authorization.getPrincipalName());

		assertThat(accessTokenAuthentication.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthentication.getAccessToken().getTokenValue()).isEqualTo(NEW_ACCESS_TOKEN_VALUE);
		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).containsAll(this.existingAccessToken.getScopes());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(accessTokenAuthentication.getRegisteredClient()).isEqualTo(this.registeredClient);
	}

	@Test
	public void authenticateWhenRefreshTokenExistsThenUpdatesAuthorization() {
		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(this.authorization);

		OAuth2RefreshTokenAuthenticationToken token = new OAuth2RefreshTokenAuthenticationToken(REFRESH_TOKEN_VALUE, this.clientPrincipal);
		this.provider.authenticate(token);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(updatedAuthorization.getTokens().getAccessToken()).isNotNull();
		assertThat(updatedAuthorization.getTokens().getAccessToken().getTokenValue()).isEqualTo(NEW_ACCESS_TOKEN_VALUE);
	}

	@Test
	public void authenticateWhenClientSetToReuseRefreshTokensThenKeepsRefreshTokenValue() {
		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(this.authorization);

		RegisteredClient clientWithReuseTokensTrue = TestRegisteredClients.registeredClient()
				.tokenSettings(tokenSettings -> tokenSettings.reuseRefreshTokens(true))
				.build();

		OAuth2RefreshTokenAuthenticationToken token = new OAuth2RefreshTokenAuthenticationToken(REFRESH_TOKEN_VALUE, new OAuth2ClientAuthenticationToken(clientWithReuseTokensTrue));
		OAuth2AccessTokenAuthenticationToken authentication = (OAuth2AccessTokenAuthenticationToken) this.provider.authenticate(token);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(updatedAuthorization.getTokens().getRefreshToken()).isNotNull();
		assertThat(updatedAuthorization.getTokens().getRefreshToken()).isEqualTo(this.authorization.getTokens().getRefreshToken());
		assertThat(authentication.getRefreshToken()).isEqualTo(this.authorization.getTokens().getRefreshToken());
	}

	@Test
	public void authenticateWhenClientSetToGenerateNewRefreshTokensThenGenerateNewToken() {
		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(this.authorization);

		RegisteredClient clientWithReuseTokensFalse = TestRegisteredClients.registeredClient()
															.tokenSettings(tokenSettings -> tokenSettings.reuseRefreshTokens(false))
															.build();

		OAuth2RefreshTokenAuthenticationToken token =
				new OAuth2RefreshTokenAuthenticationToken(REFRESH_TOKEN_VALUE, new OAuth2ClientAuthenticationToken(clientWithReuseTokensFalse));

		OAuth2AccessTokenAuthenticationToken authentication = (OAuth2AccessTokenAuthenticationToken) this.provider.authenticate(token);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(updatedAuthorization.getTokens().getRefreshToken()).isNotNull();
		assertThat(updatedAuthorization.getTokens().getRefreshToken()).isNotEqualTo(this.authorization.getTokens().getRefreshToken());
		assertThat(authentication.getRefreshToken()).isNotEqualTo(this.authorization.getTokens().getRefreshToken());
	}

	@Test
	public void authenticateWhenRefreshTokenHasScopesThenIncludeScopes() {
		Set<String> requestedScopes = new HashSet<>();
		requestedScopes.add("email");
		requestedScopes.add("openid");

		OAuth2RefreshTokenAuthenticationToken tokenWithScopes
				= new OAuth2RefreshTokenAuthenticationToken(this.clientPrincipal, REFRESH_TOKEN_VALUE, requestedScopes);

		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(this.authorization);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.provider.authenticate(tokenWithScopes);

		assertThat(accessTokenAuthentication.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).containsAll(requestedScopes);
	}

	@Test
	public void authenticateWhenRefreshTokenHasNotApprovedScopesThenThrowException() {
		Set<String> requestedScopes = new HashSet<>();
		requestedScopes.add("email");
		requestedScopes.add("another-scope");

		OAuth2RefreshTokenAuthenticationToken tokenWithScopes
				= new OAuth2RefreshTokenAuthenticationToken(this.clientPrincipal, REFRESH_TOKEN_VALUE, requestedScopes);

		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(this.authorization);

		assertThatThrownBy(() -> this.provider.authenticate(tokenWithScopes))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting((Throwable e) -> ((OAuth2AuthenticationException) e).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void authenticateWhenRefreshTokenDoesNotExistThenThrowException() {
		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(null);

		OAuth2RefreshTokenAuthenticationToken token = new OAuth2RefreshTokenAuthenticationToken(REFRESH_TOKEN_VALUE, this.clientPrincipal);
		assertThatThrownBy(() -> this.provider.authenticate(token))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient.getClientId(), null);
		OAuth2RefreshTokenAuthenticationToken token = new OAuth2RefreshTokenAuthenticationToken(REFRESH_TOKEN_VALUE, clientPrincipal);

		Assertions.assertThatThrownBy(() -> this.provider.authenticate(token))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenRefreshTokenHasExpiredThenThrowException() {
		OAuth2RefreshToken expiredRefreshToken = new OAuth2RefreshToken(REFRESH_TOKEN_VALUE, Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));
		OAuth2Authorization authorizationWithExpiredRefreshToken =
				OAuth2Authorization
						.from(this.authorization)
						.tokens(OAuth2Tokens.from(this.authorization.getTokens()).refreshToken(expiredRefreshToken).build())
						.build();

		OAuth2RefreshTokenAuthenticationToken token
				= new OAuth2RefreshTokenAuthenticationToken(REFRESH_TOKEN_VALUE, this.clientPrincipal);

		when(this.authorizationService.findByToken(REFRESH_TOKEN_VALUE, TokenType.REFRESH_TOKEN))
				.thenReturn(authorizationWithExpiredRefreshToken);

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting((Throwable e) -> ((OAuth2AuthenticationException) e).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}
}
