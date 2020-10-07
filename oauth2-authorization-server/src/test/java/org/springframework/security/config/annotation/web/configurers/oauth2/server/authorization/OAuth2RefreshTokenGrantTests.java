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

import java.time.Instant;

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
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Alexey Nesterov
 * @since 0.0.3
 */
public class OAuth2RefreshTokenGrantTests {

	private static final String TEST_REFRESH_TOKEN = "test-refresh-token";

	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	private RegisteredClient registeredClient;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authorizationService = mock(OAuth2AuthorizationService.class);
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);

		this.registeredClient = TestRegisteredClients.registeredClient2().build();

		this.spring.register(OAuth2RefreshTokenGrantTests.AuthorizationServerConfiguration.class).autowire();
	}

	@Test
	public void requestWhenRefreshTokenExists() throws Exception {
		when(registeredClientRepository.findByClientId(eq(this.registeredClient.getClientId())))
				.thenReturn(this.registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient)
				.tokens(OAuth2Tokens.builder()
						.refreshToken(new OAuth2RefreshToken(TEST_REFRESH_TOKEN, Instant.now(), Instant.now().plusSeconds(60)))
						.accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now(), Instant.now().plusSeconds(10)))
						.build())
				.build();

		when(authorizationService.findByToken(TEST_REFRESH_TOKEN, TokenType.REFRESH_TOKEN))
				.thenReturn(authorization);

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.param(OAuth2ParameterNames.REFRESH_TOKEN, TEST_REFRESH_TOKEN)
				.with(httpBasic(this.registeredClient.getClientId(), this.registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty());
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
		KeyManager keyManager() { return new StaticKeyGeneratingKeyManager(); }
	}
}
