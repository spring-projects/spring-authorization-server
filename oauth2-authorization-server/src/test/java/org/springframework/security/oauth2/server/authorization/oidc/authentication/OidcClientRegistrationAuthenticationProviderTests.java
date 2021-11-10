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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.TestJoseHeaders;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OidcClientRegistrationAuthenticationProvider}.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 */
public class OidcClientRegistrationAuthenticationProviderTests {
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2AuthorizationService authorizationService;
	private JwtEncoder jwtEncoder;
	private ProviderSettings providerSettings;
	private OidcClientRegistrationAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		this.providerSettings = ProviderSettings.builder().build();
		this.authenticationProvider = new OidcClientRegistrationAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService, this.jwtEncoder);
		this.authenticationProvider.setProviderSettings(this.providerSettings);
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcClientRegistrationAuthenticationProvider(null, this.authorizationService, this.jwtEncoder))
				.withMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcClientRegistrationAuthenticationProvider(this.registeredClientRepository, null, this.jwtEncoder))
				.withMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenJwtEncoderNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcClientRegistrationAuthenticationProvider(this.registeredClientRepository, this.authorizationService, null))
				.withMessage("jwtEncoder cannot be null");
	}

	@Test
	public void supportsWhenTypeOidcClientRegistrationAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OidcClientRegistrationAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenPrincipalNotOAuth2TokenAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		JwtAuthenticationToken principal = new JwtAuthenticationToken(createJwtClientRegistration());
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
	}

	@Test
	public void authenticateWhenAccessTokenNotFoundThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientRegistration();
		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(
				eq(jwt.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenNotActiveThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		authorization = OidcAuthenticationProviderUtils.invalidate(authorization, jwtAccessToken);
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenClientRegistrationRequestAndAccessTokenNotAuthorizedThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwt(Collections.singleton("unauthorized.scope"));
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_unauthorized.scope"));
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenClientRegistrationRequestAndAccessTokenContainsRequiredScopeAndAdditionalScopeThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwt(new HashSet<>(Arrays.asList("client.create", "scope1")));
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create", "SCOPE_scope1"));
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com")
				.build();

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenClientRegistrationRequestAndInvalidRedirectUriThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("invalid uri")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo("invalid_redirect_uri");
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenClientRegistrationRequestAndRedirectUriContainsFragmentThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("https://client.example.com#fragment")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo("invalid_redirect_uri");
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenClientRegistrationRequestAndValidAccessTokenThenReturnClientRegistration() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientRegistration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwtClientConfiguration());

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create"));
		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, clientRegistration);

		OidcClientRegistrationAuthenticationToken authenticationResult =
				(OidcClientRegistrationAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<RegisteredClient> registeredClientCaptor = ArgumentCaptor.forClass(RegisteredClient.class);
		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);

		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).save(registeredClientCaptor.capture());
		verify(this.authorizationService, times(2)).save(authorizationCaptor.capture());
		verify(this.jwtEncoder).encode(any(), any());

		// assert "registration" access token, which should be used for subsequent calls to client configuration endpoint
		OAuth2Authorization authorizationResult = authorizationCaptor.getAllValues().get(0);
		assertThat(authorizationResult.getAccessToken().getToken().getScopes())
				.containsExactly("client.read");
		assertThat(authorizationResult.getAccessToken().isActive()).isTrue();
		assertThat(authorizationResult.getRefreshToken()).isNull();

		// assert "initial" access token is invalidated
		authorizationResult = authorizationCaptor.getAllValues().get(1);
		assertThat(authorizationResult.getAccessToken().isInvalidated()).isTrue();
		if (authorizationResult.getRefreshToken() != null) {
			assertThat(authorizationResult.getRefreshToken().isInvalidated()).isTrue();
		}

		RegisteredClient registeredClientResult = registeredClientCaptor.getValue();
		assertThat(registeredClientResult.getId()).isNotNull();
		assertThat(registeredClientResult.getClientId()).isNotNull();
		assertThat(registeredClientResult.getClientIdIssuedAt()).isNotNull();
		assertThat(registeredClientResult.getClientSecret()).isNotNull();
		assertThat(registeredClientResult.getClientName()).isEqualTo(clientRegistration.getClientName());
		assertThat(registeredClientResult.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registeredClientResult.getRedirectUris()).containsExactly("https://client.example.com");
		assertThat(registeredClientResult.getAuthorizationGrantTypes())
				.containsExactlyInAnyOrder(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(registeredClientResult.getScopes()).containsExactlyInAnyOrder("scope1", "scope2");
		assertThat(registeredClientResult.getClientSettings().isRequireProofKey()).isTrue();
		assertThat(registeredClientResult.getClientSettings().isRequireAuthorizationConsent()).isTrue();
		assertThat(registeredClientResult.getTokenSettings().getIdTokenSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);

		OidcClientRegistration clientRegistrationResult = authenticationResult.getClientRegistration();
		assertThat(clientRegistrationResult.getClientId()).isEqualTo(registeredClientResult.getClientId());
		assertThat(clientRegistrationResult.getClientIdIssuedAt()).isEqualTo(registeredClientResult.getClientIdIssuedAt());
		assertThat(clientRegistrationResult.getClientSecret()).isEqualTo(registeredClientResult.getClientSecret());
		assertThat(clientRegistrationResult.getClientSecretExpiresAt()).isEqualTo(registeredClientResult.getClientSecretExpiresAt());
		assertThat(clientRegistrationResult.getClientName()).isEqualTo(registeredClientResult.getClientName());
		assertThat(clientRegistrationResult.getRedirectUris())
				.containsExactlyInAnyOrderElementsOf(registeredClientResult.getRedirectUris());

		List<String> grantTypes = new ArrayList<>();
		registeredClientResult.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
				grantTypes.add(authorizationGrantType.getValue()));
		assertThat(clientRegistrationResult.getGrantTypes()).containsExactlyInAnyOrderElementsOf(grantTypes);

		assertThat(clientRegistrationResult.getResponseTypes())
				.containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistrationResult.getScopes())
				.containsExactlyInAnyOrderElementsOf(registeredClientResult.getScopes());
		assertThat(clientRegistrationResult.getTokenEndpointAuthenticationMethod())
				.isEqualTo(registeredClientResult.getClientAuthenticationMethods().iterator().next().getValue());
		assertThat(clientRegistrationResult.getIdTokenSignedResponseAlgorithm())
				.isEqualTo(registeredClientResult.getTokenSettings().getIdTokenSignatureAlgorithm().getName());

		String expectedRegistrationClientUrl = UriComponentsBuilder.fromUriString(issuer)
				.path(this.providerSettings.getOidcClientRegistrationEndpoint())
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClientResult.getClientId()).toUriString();

		assertThat(clientRegistrationResult.getRegistrationClientUrl().toString()).isEqualTo(expectedRegistrationClientUrl);
		assertThat(clientRegistrationResult.getRegistrationAccessToken()).isEqualTo(jwt.getTokenValue());
	}

	@Test
	public void authenticateWhenClientConfigurationRequestAndAccessTokenNotAuthorizedThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwt(Collections.singleton("unauthorized.scope"));
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_unauthorized.scope"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenClientConfigurationRequestAndAccessTokenContainsRequiredScopeAndAdditionalScopeThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwt(new HashSet<>(Arrays.asList("client.read", "scope1")));
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.read", "SCOPE_scope1"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenClientConfigurationRequestAndRegisteredClientNotFoundThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientConfiguration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).findByClientId(
				eq(registeredClient.getClientId()));
	}

	@Test
	public void authenticateWhenClientConfigurationRequestClientIdNotEqualToAuthorizedClientThenThrowOAuth2AuthenticationException() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientConfiguration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient()
				.id("registration-2").clientId("client-2").build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				authorizedRegisteredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, registeredClient.getClientId());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).findByClientId(
				eq(registeredClient.getClientId()));
	}

	@Test
	public void authenticateWhenClientConfigurationRequestAndValidAccessTokenThenReturnClientRegistration() {
		String issuer = "https://example.com/issuer1";
		Jwt jwt = createJwtClientConfiguration();
		OAuth2AccessToken jwtAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(),
				jwt.getExpiresAt(), jwt.getClaim(OAuth2ParameterNames.SCOPE));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientName("client-name")
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, jwtAccessToken, jwt.getClaims()).build();
		when(this.authorizationService.findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.read"));

		OidcClientRegistrationAuthenticationToken authentication = new OidcClientRegistrationAuthenticationToken(
				issuer, principal, registeredClient.getClientId());

		OidcClientRegistrationAuthenticationToken authenticationResult =
				(OidcClientRegistrationAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		verify(this.authorizationService).findByToken(
				eq(jwtAccessToken.getTokenValue()), eq(OAuth2TokenType.ACCESS_TOKEN));
		verify(this.registeredClientRepository).findByClientId(
				eq(registeredClient.getClientId()));

		// verify that the "registration" access token is not invalidated after it is used
		verify(this.authorizationService, never()).save(eq(authorization));
		assertThat(authorization.getAccessToken().isInvalidated()).isFalse();

		OidcClientRegistration clientRegistrationResult = authenticationResult.getClientRegistration();
		assertThat(clientRegistrationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(clientRegistrationResult.getClientIdIssuedAt()).isEqualTo(registeredClient.getClientIdIssuedAt());
		assertThat(clientRegistrationResult.getClientSecret()).isEqualTo(registeredClient.getClientSecret());
		assertThat(clientRegistrationResult.getClientSecretExpiresAt()).isEqualTo(registeredClient.getClientSecretExpiresAt());
		assertThat(clientRegistrationResult.getClientName()).isEqualTo(registeredClient.getClientName());
		assertThat(clientRegistrationResult.getRedirectUris())
				.containsExactlyInAnyOrderElementsOf(registeredClient.getRedirectUris());

		List<String> grantTypes = new ArrayList<>();
		registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
				grantTypes.add(authorizationGrantType.getValue()));
		assertThat(clientRegistrationResult.getGrantTypes()).containsExactlyInAnyOrderElementsOf(grantTypes);

		assertThat(clientRegistrationResult.getResponseTypes())
				.containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistrationResult.getScopes())
				.containsExactlyInAnyOrderElementsOf(registeredClient.getScopes());
		assertThat(clientRegistrationResult.getTokenEndpointAuthenticationMethod())
				.isEqualTo(registeredClient.getClientAuthenticationMethods().iterator().next().getValue());
		assertThat(clientRegistrationResult.getIdTokenSignedResponseAlgorithm())
				.isEqualTo(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName());

		String expectedRegistrationClientUrl = UriComponentsBuilder.fromUriString(issuer)
				.path(this.providerSettings.getOidcClientRegistrationEndpoint())
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId()).toUriString();

		assertThat(clientRegistrationResult.getRegistrationClientUrl().toString()).isEqualTo(expectedRegistrationClientUrl);
		assertThat(clientRegistrationResult.getRegistrationAccessToken()).isNull();
	}

	private static Jwt createJwtClientRegistration() {
		return createJwt(Collections.singleton("client.create"));
	}

	private static Jwt createJwtClientConfiguration() {
		return createJwt(Collections.singleton("client.read"));
	}

	private static Jwt createJwt(Set<String> scopes) {
		// @formatter:off
		JoseHeader joseHeader = TestJoseHeaders.joseHeader()
				.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet()
				.claim(OAuth2ParameterNames.SCOPE, scopes)
				.build();
		Jwt jwt = Jwt.withTokenValue("jwt-access-token")
				.headers(headers -> headers.putAll(joseHeader.getHeaders()))
				.claims(claims -> claims.putAll(jwtClaimsSet.getClaims()))
				.build();
		// @formatter:on
		return jwt;
	}

}
