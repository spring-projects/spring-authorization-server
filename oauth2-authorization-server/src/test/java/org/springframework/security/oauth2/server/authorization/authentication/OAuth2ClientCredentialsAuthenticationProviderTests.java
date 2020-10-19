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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jose.JoseHeaderNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2ClientCredentialsAuthenticationProvider}.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 */
public class OAuth2ClientCredentialsAuthenticationProviderTests {
	private RegisteredClient registeredClient;
	private OAuth2AuthorizationService authorizationService;
	private JwtEncoder jwtEncoder;
	private OAuth2ClientCredentialsAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.registeredClient = TestRegisteredClients.registeredClient().build();
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		this.authenticationProvider = new OAuth2ClientCredentialsAuthenticationProvider(
				this.authorizationService, this.jwtEncoder);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientCredentialsAuthenticationProvider(null, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenJwtEncoderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientCredentialsAuthenticationProvider(this.authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtEncoder cannot be null");
	}

	@Test
	public void supportsWhenSupportedAuthenticationThenTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedAuthenticationThenFalse() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isFalse();
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				this.registeredClient.getClientId(), this.registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				this.registeredClient.getClientId(), this.registeredClient.getClientSecret(), null);
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidScopeThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, Collections.singleton("invalid-scope"));

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void authenticateWhenScopeRequestedThenAccessTokenContainsScope() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		Set<String> requestedScope = Collections.singleton("openid");
		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, requestedScope);

		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt());

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);
		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).isEqualTo(requestedScope);
	}

	@Test
	public void authenticateWhenValidAuthenticationThenReturnAccessToken() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal);

		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt());

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();

		assertThat(authorization.getRegisteredClientId()).isEqualTo(clientPrincipal.getRegisteredClient().getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(clientPrincipal.getName());
		assertThat(authorization.getTokens().getAccessToken()).isNotNull();
		assertThat(authorization.getTokens().getAccessToken().getScopes()).isEqualTo(clientPrincipal.getRegisteredClient().getScopes());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(authorization.getTokens().getAccessToken());
	}

	private static Jwt createJwt() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return Jwt.withTokenValue("token")
				.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.build();
	}
}
