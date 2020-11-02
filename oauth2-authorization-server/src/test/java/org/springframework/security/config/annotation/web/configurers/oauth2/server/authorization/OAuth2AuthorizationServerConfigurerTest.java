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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.config.util.JwtAssertions;
import org.springframework.security.crypto.key.AsymmetricKey;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.crypto.key.StaticKeyGeneratingCryptoKeySource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.JwtBuilder;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenIssuer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenMetadata;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationGrantContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenResult;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class OAuth2AuthorizationServerConfigurerTest {

	private static final String TEST_REFRESH_TOKEN = "test-refresh-token";
	private static final String TEST_AUTHORIZATION_CODE = "test-authorization-code";

	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static CryptoKeySource keySource;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	private RegisteredClient registeredClient;
	private JwtAssertions validJwtToken;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authorizationService = mock(OAuth2AuthorizationService.class);
		keySource = new StaticKeyGeneratingCryptoKeySource();
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);

		this.registeredClient = TestRegisteredClients.registeredClient2().tokenSettings(tokenSettings -> tokenSettings.reuseRefreshTokens(false)).build();
		when(registeredClientRepository.findByClientId(eq(this.registeredClient.getClientId())))
				.thenReturn(this.registeredClient);

		AsymmetricKey key = (AsymmetricKey) keySource.getKeys().stream()
				.filter(cryptoKey -> "RSA".equals(cryptoKey.getAlgorithm()))
				.findFirst().orElseThrow(() -> new AssertionError("Public Key not found"));

		RSAPublicKey publicKey = (RSAPublicKey) key.getPublicKey();

		JwtDecoder testJwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
		this.validJwtToken = new JwtAssertions(testJwtDecoder);
	}

	// Refresh Token Grant type

	@Test
	public void initRefreshTokenGrantWhenClaimsCustomizerProvidedThenCustomizeAccessTokenClaims() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class, JwtTokenCustomizerConfiguration.class).autowire();

		mockExistingAuthorizationWithRefreshToken();

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.param(OAuth2ParameterNames.REFRESH_TOKEN, TEST_REFRESH_TOKEN)
				.with(httpBasic(this.registeredClient.getClientId(), this.registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").value(validJwtToken.withClaim("test-claim", "test-claim-value")));

		verify(authorizationService).save(ArgumentMatchers.argThat(savedAuthorization -> {
			OAuth2AccessToken accessToken = savedAuthorization.getTokens().getAccessToken();
			OAuth2TokenMetadata tokenMetadata = savedAuthorization.getTokens().getTokenMetadata(accessToken);
			Jwt jwt = tokenMetadata.getMetadata(OAuth2TokenMetadata.TOKEN);
			return "test-claim-value".equals(jwt.getClaims().get("test-claim"));
		}));
	}

	@Test
	public void initRefreshTokenGrantWhenAccessTokenIssuerProvidedThenUseThatAccessTokenIssuer() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class, TokenIssuerConfiguration.class).autowire();

		mockExistingAuthorizationWithRefreshToken();

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.param(OAuth2ParameterNames.REFRESH_TOKEN, TEST_REFRESH_TOKEN)
				.with(httpBasic(this.registeredClient.getClientId(), this.registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").value(MockAccessTokenIssuer.MOCK_TOKEN_VALUE));
	}

	// Authorization Code Grant type

	@Test
	public void initAuthorizationCodeGrantWhenClaimsCustomizerProvidedThenCustomizeAccessTokenClaims() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class, JwtTokenCustomizerConfiguration.class).autowire();

		mockExistingAuthorizationWithAuthorizationCode();

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.param(OAuth2ParameterNames.CODE, TEST_AUTHORIZATION_CODE)
				.param(OAuth2ParameterNames.REDIRECT_URI, this.registeredClient.getRedirectUris().iterator().next())
				.with(httpBasic(this.registeredClient.getClientId(), this.registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").value(validJwtToken.withClaim("test-claim", "test-claim-value")));

		verify(authorizationService).save(ArgumentMatchers.argThat(savedAuthorization -> {
			OAuth2AccessToken accessToken = savedAuthorization.getTokens().getAccessToken();
			OAuth2TokenMetadata tokenMetadata = savedAuthorization.getTokens().getTokenMetadata(accessToken);
			Jwt jwt = tokenMetadata.getMetadata(OAuth2TokenMetadata.TOKEN);
			return "test-claim-value".equals(jwt.getClaims().get("test-claim"));
		}));
	}

	@Test
	public void initAuthorizationCodeGrantWhenAccessTokenIssuerProvidedThenUseThatAccessTokenIssuer() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class, TokenIssuerConfiguration.class).autowire();

		mockExistingAuthorizationWithAuthorizationCode();

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.param(OAuth2ParameterNames.CODE, TEST_AUTHORIZATION_CODE)
				.param(OAuth2ParameterNames.REDIRECT_URI, this.registeredClient.getRedirectUris().iterator().next())
				.with(httpBasic(this.registeredClient.getClientId(), this.registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").value(MockAccessTokenIssuer.MOCK_TOKEN_VALUE));
	}

	// Client Credentials Grant type

	@Test
	public void initClientCredentialsWhenClaimsCustomizerProvidedThenCustomizeAccessTokenClaims() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class, JwtTokenCustomizerConfiguration.class).autowire();
		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.with(httpBasic(this.registeredClient.getClientId(), this.registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").value(validJwtToken.withClaim("test-claim", "test-claim-value")));

		verify(authorizationService).save(ArgumentMatchers.argThat(savedAuthorization -> {
			OAuth2AccessToken accessToken = savedAuthorization.getTokens().getAccessToken();
			OAuth2TokenMetadata tokenMetadata = savedAuthorization.getTokens().getTokenMetadata(accessToken);
			Jwt jwt = tokenMetadata.getMetadata(OAuth2TokenMetadata.TOKEN);
			return "test-claim-value".equals(jwt.getClaims().get("test-claim"));
		}));
	}

	@Test
	public void initClientCredentialsWhenAccessTokenIssuerProvidedThenUseThatAccessTokenIssuer() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class, TokenIssuerConfiguration.class).autowire();
		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.with(httpBasic(this.registeredClient.getClientId(), this.registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").value(MockAccessTokenIssuer.MOCK_TOKEN_VALUE));
	}

	private void mockExistingAuthorizationWithRefreshToken() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient)
				.tokens(OAuth2Tokens.builder()
						.refreshToken(new OAuth2RefreshToken2(TEST_REFRESH_TOKEN, Instant.now(), Instant.now().plusSeconds(60)))
						.accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now(), Instant.now().plusSeconds(10)))
						.build())
				.build();

		when(authorizationService.findByToken(TEST_REFRESH_TOKEN, TokenType.REFRESH_TOKEN))
				.thenReturn(authorization);
	}

	private void mockExistingAuthorizationWithAuthorizationCode() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient)
				.tokens(OAuth2Tokens.builder()
						.token(new OAuth2AuthorizationCode(TEST_AUTHORIZATION_CODE, Instant.now(), Instant.now().plusSeconds(60)))
						.build())
				.build();

		when(authorizationService.findByToken(TEST_AUTHORIZATION_CODE, TokenType.AUTHORIZATION_CODE))
				.thenReturn(authorization);
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			return registeredClientRepository;
		}

		@Bean
		OAuth2AuthorizationService authorizationService() {
			return authorizationService;
		}

		@Bean
		CryptoKeySource keyManager() { return keySource; }
	}

	static class JwtTokenCustomizerConfiguration {
		@Bean
		OAuth2TokenCustomizer<JwtBuilder> accessTokenCustomizer() {
			return builder -> builder.claims(claims -> claims.put("test-claim", "test-claim-value"));
		}
	}

	static class TokenIssuerConfiguration {
		@Bean
		OAuth2TokenIssuer<OAuth2AccessToken> accessTokenIssuer() {
			return new MockAccessTokenIssuer();
		}
	}

	private static class MockAccessTokenIssuer implements OAuth2TokenIssuer<OAuth2AccessToken> {

		private final static String MOCK_TOKEN_VALUE = UUID.randomUUID().toString();

		@Override
		public OAuth2TokenResult<OAuth2AccessToken> issue(OAuth2AuthorizationGrantContext tokenRequest) {
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plusSeconds(60);
			OAuth2TokenMetadata tokenMetadata = OAuth2TokenMetadata.builder().metadata(OAuth2TokenMetadata.TOKEN, MOCK_TOKEN_VALUE).build();
			return OAuth2TokenResult.of(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, MOCK_TOKEN_VALUE, issuedAt, expiresAt), tokenMetadata);
		}
	}
}
