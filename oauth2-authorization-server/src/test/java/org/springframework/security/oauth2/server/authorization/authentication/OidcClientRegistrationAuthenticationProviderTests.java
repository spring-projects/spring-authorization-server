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

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Ovidiu Popa
 * @since 0.1.1
 */
public class OidcClientRegistrationAuthenticationProviderTests {

	private OAuth2AuthorizationService authorizationService;
	private OidcClientRegistrationAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authenticationProvider = new OidcClientRegistrationAuthenticationProvider(this.authorizationService);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OidcClientRegistrationAuthenticationProvider(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void supportsWhenTypeJwtAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(JwtAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenAccessTokenNotFoundThenThrowOAuth2AuthenticationException() {
		JwtAuthenticationToken authentication = buildJwtAuthenticationToken("client-registration-token",  "SCOPE_client.create");

		when(authorizationService.findByToken(
				eq("client-registration-token"), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(null);


		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);

	}

	@Test
	public void authenticateWhenAccessTokenInvalidatedThenThrowOAuth2AuthenticationException() {

		JwtAuthenticationToken authentication = buildJwtAuthenticationToken("client-registration-token",  "SCOPE_client.create");

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"client-registration-token", Instant.now().minusSeconds(120), Instant.now().plusSeconds(1000));

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization()
				.token(accessToken, (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
				.build();

		when(authorizationService.findByToken(
				eq("client-registration-token"), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenAccessTokenWithoutClientCreateScopeThenThrowOAuth2AuthenticationException() {

		JwtAuthenticationToken authentication = buildJwtAuthenticationToken("client-registration-token",  "SCOPE_scope1");

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"client-registration-token", Instant.now().minusSeconds(120), Instant.now().plusSeconds(1000),
				new HashSet<>(Collections.singletonList("scope1")));

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization()
				.token(accessToken)
				.build();

		when(authorizationService.findByToken(
				eq("client-registration-token"), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenValidAccessTokenThenInvalidated() {
		JwtAuthenticationToken authentication = buildJwtAuthenticationToken("client-registration-token", "SCOPE_client.create");

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"client-registration-token", Instant.now().minusSeconds(120), Instant.now().plusSeconds(1000),
				new HashSet<>(Collections.singletonList("client.create")));

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization()
				.token(accessToken)
				.build();

		when(authorizationService.findByToken(
				eq("client-registration-token"), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization capturedAuthorization = authorizationCaptor.getValue();

		assertThat(capturedAuthorization.getAccessToken()).isNotNull();
		assertThat(capturedAuthorization.getAccessToken().isInvalidated()).isTrue();
	}

	private static JwtAuthenticationToken buildJwtAuthenticationToken(String tokenValue, String... authorities) {
		Jwt jwt = Jwt.withTokenValue(tokenValue)
				.header("alg", "none")
				.claim("sub", "client")
				.build();
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList(authorities);
		JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, grantedAuthorities);
		jwtAuthenticationToken.setAuthenticated(true);
		return jwtAuthenticationToken;
	}
}
