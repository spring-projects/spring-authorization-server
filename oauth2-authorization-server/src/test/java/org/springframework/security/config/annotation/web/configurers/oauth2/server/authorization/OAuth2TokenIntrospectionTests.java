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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

/**
 * Integration tests for the OAuth 2.0 Token Introspection endpoint.
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionTests {
	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static JWKSource<SecurityContext> jwkSource;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authorizationService = mock(OAuth2AuthorizationService.class);
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);
	}

	@Test
	public void requestWhenIntrospectValidRefreshTokenThenActiveResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken token = authorization.getRefreshToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.REFRESH_TOKEN;
		when(authorizationService.findByToken(eq(token.getTokenValue()), isNull())).thenReturn(authorization);

		// @formatter:off
		this.mvc.perform(
				MockMvcRequestBuilders.post(OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI)
						.params(getTokenIntrospectionRequestParameters(token, tokenType))
						.with(httpBasic(registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.active").value(true))
				.andExpect(jsonPath("$.client_id").value("client-1"))
				.andExpect(jsonPath("$.iat").isNotEmpty())
				.andExpect(jsonPath("$.exp").isNotEmpty())
				.andExpect(jsonPath("$.username").value("principal"));
		// @formatter:on

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByToken(eq(token.getTokenValue()), isNull());
	}

	@Test
	public void requestWhenIntrospectValidAccessTokenThenActiveResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "token", issuedAt, expiresAt,
				new HashSet<>(Arrays.asList("scope1", "Scope2")));
		OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).token(accessToken)
				.build();

		when(authorizationService.findByToken(eq(accessToken.getTokenValue()), isNull())).thenReturn(authorization);

		// @formatter:off
		this.mvc.perform(
				MockMvcRequestBuilders.post(OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI)
						.params(getTokenIntrospectionRequestParameters(accessToken, tokenType))
						.with(httpBasic(registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.active").value(true))
				.andExpect(jsonPath("$.client_id").value("client-1"))
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andExpect(jsonPath("$.token_type").value(OAuth2AccessToken.TokenType.BEARER.getValue()))
				.andExpect(jsonPath("$.iat").isNotEmpty())
				.andExpect(jsonPath("$.exp").isNotEmpty())
				.andExpect(jsonPath("$.username").value("principal"));
		// @formatter:on

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByToken(eq(accessToken.getTokenValue()), isNull());
	}

	@Test
	public void requestWhenIntrospectTokenIssuedToDifferentClientThenActiveResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient2().build();
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "token", issuedAt, expiresAt,
				new HashSet<>(Arrays.asList("scope1", "Scope2")));
		OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient2).token(accessToken)
				.build();

		when(authorizationService.findByToken(eq(accessToken.getTokenValue()), isNull())).thenReturn(authorization);

		// @formatter:off
		this.mvc.perform(
				MockMvcRequestBuilders.post(OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI)
						.params(getTokenIntrospectionRequestParameters(accessToken, tokenType))
						.with(httpBasic(registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.active").value(true))
				.andExpect(jsonPath("$.client_id").value("client-1"))
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andExpect(jsonPath("$.token_type").value(OAuth2AccessToken.TokenType.BEARER.getValue()))
				.andExpect(jsonPath("$.iat").isNotEmpty())
				.andExpect(jsonPath("$.exp").isNotEmpty())
				.andExpect(jsonPath("$.username").value("principal"));
		// @formatter:on

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByToken(eq(accessToken.getTokenValue()), isNull());
	}

	private static MultiValueMap<String, String> getTokenIntrospectionRequestParameters(AbstractOAuth2Token token,
			OAuth2TokenType tokenType) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames2.TOKEN, token.getTokenValue());
		parameters.set(OAuth2ParameterNames2.TOKEN_TYPE_HINT, tokenType.getValue());
		return parameters;
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
		JWKSource<SecurityContext> jwkSource() {
			return jwkSource;
		}
	}
}
