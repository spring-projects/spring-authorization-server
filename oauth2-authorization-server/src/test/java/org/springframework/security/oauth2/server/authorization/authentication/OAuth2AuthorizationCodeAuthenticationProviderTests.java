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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jose.JoseHeaderNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2AuthorizationCodeAuthenticationProvider}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeAuthenticationProviderTests {
	private final String PLAIN_CODE_CHALLENGE = "pkce-key";
	private final String PLAIN_CODE_VERIFIER = PLAIN_CODE_CHALLENGE;

	// See RFC 7636: Appendix B.  Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private final String AUTHORIZATION_CODE = "code";

	private RegisteredClient registeredClient;
	private RegisteredClient otherRegisteredClient;
	private RegisteredClient registeredClientRequiresProofKey;
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2AuthorizationService authorizationService;
	private JwtEncoder jwtEncoder;
	private OAuth2AuthorizationCodeAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.registeredClient = TestRegisteredClients.registeredClient().build();
		this.otherRegisteredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRequiresProofKey = TestRegisteredClients.registeredClient()
				.id("registration-3")
				.clientId("client-3")
				.clientSettings(new ClientSettings().requireProofKey(true))
				.build();
		this.registeredClientRepository = new InMemoryRegisteredClientRepository(
				this.registeredClient,
				this.otherRegisteredClient,
				this.registeredClientRequiresProofKey
		);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		this.authenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService, this.jwtEncoder);
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationProvider(null, this.authorizationService, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationProvider(this.registeredClientRepository, null, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenJwtEncoderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationProvider(this.registeredClientRepository, this.authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtEncoder cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2AuthorizationCodeAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				this.registeredClient.getClientId(), this.registeredClient.getClientSecret());
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, null, null);
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
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidCodeThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenCodeIssuedToAnotherClientThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		when(this.authorizationService.findByToken(eq("code"), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				TestRegisteredClients.registeredClient2().build());
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenInvalidRedirectUriThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		when(this.authorizationService.findByToken(eq("code"), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, authorizationRequest.getRedirectUri() + "-invalid", null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenValidCodeThenReturnAccessToken() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		when(this.authorizationService.findByToken(eq("code"), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt());

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId()).isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(updatedAuthorization.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(updatedAuthorization.getAccessToken());
	}

	@Test
	public void authenticateWhenRequireProofKeyAndMissingPkceCodeChallengeInAuthorizationRequestThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClientRequiresProofKey).build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken(
						AUTHORIZATION_CODE,
						registeredClientRequiresProofKey.getClientId(),
						authorizationRequest.getRedirectUri(),
						Collections.singletonMap(PkceParameterNames.CODE_VERIFIER, PLAIN_CODE_VERIFIER)
				);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenRequireProofKeyAndUnsupportedCodeChallengeMethodInAuthorizationRequestThenThrowOAuth2AuthenticationException() {
		Map<String, Object> pkceParameters = new HashMap<>();
		pkceParameters.put(PkceParameterNames.CODE_CHALLENGE, PLAIN_CODE_CHALLENGE);
		// This should never happen: the Authorization endpoint should not allow it
		pkceParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "unsupported-challenge-method");
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClientRequiresProofKey, pkceParameters)
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken(
						AUTHORIZATION_CODE,
						registeredClientRequiresProofKey.getClientId(),
						authorizationRequest.getRedirectUri(),
						Collections.singletonMap(PkceParameterNames.CODE_VERIFIER, PLAIN_CODE_VERIFIER)
				);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
	}

	@Test
	public void authenticateWhenPublicClientAndClientIdNotMatchingThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken(
						AUTHORIZATION_CODE,
						otherRegisteredClient.getClientId(),
						authorizationRequest.getRedirectUri(),
						Collections.singletonMap(PkceParameterNames.CODE_VERIFIER, PLAIN_CODE_VERIFIER)
				);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenPublicClientAndUnknownClientIdThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken(
						AUTHORIZATION_CODE,
						"invalid-client-id",
						authorizationRequest.getRedirectUri(),
						Collections.singletonMap(PkceParameterNames.CODE_VERIFIER, PLAIN_CODE_CHALLENGE)
				);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenPublicClientAndMissingCodeVerifierThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken(
						AUTHORIZATION_CODE,
						authorizationRequest.getClientId(),
						authorizationRequest.getRedirectUri(),
						null
				);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenPrivateClientAndRequireProofKeyAndMissingCodeVerifierThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient);
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken(
						AUTHORIZATION_CODE,
						clientPrincipal,
						authorizationRequest.getRedirectUri(),
						null
				);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenPublicClientAndPlainMethodAndInvalidCodeVerifierThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AuthorizationCodeAuthenticationToken authentication = makeAuthorizationCodeAuthenticationToken("invalid-code-verifier");
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenPublicClientAndS256MethodAndInvalidCodeVerifierThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersS256())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AuthorizationCodeAuthenticationToken authentication = makeAuthorizationCodeAuthenticationToken("invalid-code-verifier");

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenPublicClientAndPlainMethodAndValidCodeVerifierThenReturnAccessToken() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersPlain())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);
		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt());

		OAuth2AuthorizationCodeAuthenticationToken authentication = makeAuthorizationCodeAuthenticationToken(PLAIN_CODE_VERIFIER);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		OAuth2ClientAuthenticationToken clientAuthenticationToken = (OAuth2ClientAuthenticationToken) accessTokenAuthentication.getPrincipal();
		assertThat(clientAuthenticationToken.getPrincipal()).isEqualTo(this.registeredClient.getClientId());
		assertThat(updatedAuthorization.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(updatedAuthorization.getAccessToken());
	}

	@Test
	public void authenticateWhenPublicClientAndNoMethodThenDefaultToPlainAndReturnAccessToken() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, Collections.singletonMap(PkceParameterNames.CODE_CHALLENGE, PLAIN_CODE_CHALLENGE))
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);
		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt());

		OAuth2AuthorizationCodeAuthenticationToken authentication = makeAuthorizationCodeAuthenticationToken(PLAIN_CODE_VERIFIER);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		OAuth2ClientAuthenticationToken clientAuthenticationToken = (OAuth2ClientAuthenticationToken) accessTokenAuthentication.getPrincipal();
		assertThat(clientAuthenticationToken.getPrincipal()).isEqualTo(this.registeredClient.getClientId());
		assertThat(updatedAuthorization.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(updatedAuthorization.getAccessToken());
	}


	@Test
	public void authenticateWhenPublicClientAndS256MethodAndValidCodeVerifierThenReturnAccessToken() {
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, getPkceAuthorizationParametersS256())
				.build();
		when(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);
		when(this.jwtEncoder.encode(any(), any())).thenReturn(createJwt());

		OAuth2AuthorizationCodeAuthenticationToken authentication = makeAuthorizationCodeAuthenticationToken(S256_CODE_VERIFIER);


		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				(OAuth2AccessTokenAuthenticationToken) this.authenticationProvider.authenticate(authentication);


		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		OAuth2ClientAuthenticationToken clientAuthenticationToken = (OAuth2ClientAuthenticationToken) accessTokenAuthentication.getPrincipal();
		assertThat(clientAuthenticationToken.getPrincipal()).isEqualTo(this.registeredClient.getClientId());
		assertThat(updatedAuthorization.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(updatedAuthorization.getAccessToken());
	}

	private Map<String, Object> getPkceAuthorizationParametersPlain() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "plain");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, PLAIN_CODE_CHALLENGE);
		return additionalParameters;
	}

	private Map<String, Object> getPkceAuthorizationParametersS256() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		return additionalParameters;
	}

	private OAuth2AuthorizationCodeAuthenticationToken makeAuthorizationCodeAuthenticationToken(String codeVerifier) {
		return new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE,
				registeredClient.getClientId(),
				registeredClient.getRedirectUris().iterator().next(),
				Collections.singletonMap(PkceParameterNames.CODE_VERIFIER, codeVerifier)
		);
	}

	private Jwt createJwt() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return Jwt.withTokenValue("token")
				.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.build();
	}
}
