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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

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
	private OAuth2AuthorizationService authorizationService;
	private JwtEncoder jwtEncoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;
	private OAuth2ClientCredentialsAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		this.authenticationProvider = new OAuth2ClientCredentialsAuthenticationProvider(
				this.authorizationService, this.jwtEncoder);
		this.jwtCustomizer = mock(OAuth2TokenCustomizer.class);
		this.authenticationProvider.setJwtCustomizer(this.jwtCustomizer);
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
	public void setJwtCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setJwtCustomizer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtCustomizer cannot be null");
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
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRequestTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.authorizationGrantTypes(grantTypes -> grantTypes.remove(AuthorizationGrantType.CLIENT_CREDENTIALS))
				.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidScopeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, Collections.singleton("invalid-scope"), null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void authenticateWhenScopeRequestedThenAccessTokenContainsScope() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		Set<String> requestedScope = Collections.singleton("scope1");
		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, requestedScope, null);

		when(this.jwtEncoder.encode(any(), any()))
				.thenReturn(createJwt(Collections.singleton("mapped-scoped")));

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);
		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).isEqualTo(requestedScope);
	}

	@Test
	public void authenticateWhenValidAuthenticationThenReturnAccessToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2ClientCredentialsAuthenticationToken authentication =
				new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, null, null);

		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt(registeredClient.getScopes()));

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer).customize(jwtEncodingContextCaptor.capture());
		JwtEncodingContext jwtEncodingContext = jwtEncodingContextCaptor.getValue();
		assertThat(jwtEncodingContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(jwtEncodingContext.<Authentication>getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(jwtEncodingContext.getAuthorization()).isNull();
		assertThat(jwtEncodingContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(jwtEncodingContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(jwtEncodingContext.getHeaders()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();

		assertThat(jwtEncodingContext.getAuthorizedScopes())
				.isEqualTo(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME));

		assertThat(authorization.getRegisteredClientId()).isEqualTo(clientPrincipal.getRegisteredClient().getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(clientPrincipal.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(authorization.getAccessToken()).isNotNull();
		assertThat(authorization.<Set<String>>getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME)).isNotNull();
		assertThat(authorization.getAccessToken().getToken().getScopes())
				.isEqualTo(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME));
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(authorization.getAccessToken().getToken());
	}

	private static Jwt createJwt(Set<String> scope) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return Jwt.withTokenValue("token")
				.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.claim(OAuth2ParameterNames.SCOPE, scope)
				.build();
	}
}
