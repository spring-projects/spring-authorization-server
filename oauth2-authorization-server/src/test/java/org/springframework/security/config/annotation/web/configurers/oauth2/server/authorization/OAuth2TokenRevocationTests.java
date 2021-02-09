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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Token Revocation endpoint.
 *
 * @author Joe Grandja
 */
public class OAuth2TokenRevocationTests {
	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static JWKSource<SecurityContext> jwkSource;
	private static ProviderSettings providerSettings;

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
		providerSettings = new ProviderSettings().tokenRevocationEndpoint("/test/revoke");
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);
	}

	@Test
	public void requestWhenRevokeRefreshTokenThenRevoked() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken token = authorization.getRefreshToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.REFRESH_TOKEN;
		when(authorizationService.findByToken(eq(token.getTokenValue()), isNull())).thenReturn(authorization);

		this.mvc.perform(post(OAuth2TokenRevocationEndpointFilter.DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI)
				.params(getTokenRevocationRequestParameters(token, tokenType))
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk());

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByToken(eq(token.getTokenValue()), isNull());

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = updatedAuthorization.getRefreshToken();
		assertThat(refreshToken.isInvalidated()).isTrue();
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
		assertThat(accessToken.isInvalidated()).isTrue();
	}

	@Test
	public void requestWhenRevokeAccessTokenThenRevoked() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		assertRevokeAccessTokenThenRevoked(OAuth2TokenRevocationEndpointFilter.DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI);
	}

	@Test
	public void requestWhenRevokeAccessTokenCustomEndpointThenRevoked() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomEndpoints.class).autowire();

		assertRevokeAccessTokenThenRevoked(providerSettings.tokenRevocationEndpoint());
	}

	private void assertRevokeAccessTokenThenRevoked(String tokenRevocationEndpointUri) throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken token = authorization.getAccessToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;
		when(authorizationService.findByToken(eq(token.getTokenValue()), isNull())).thenReturn(authorization);

		this.mvc.perform(post(tokenRevocationEndpointUri)
				.params(getTokenRevocationRequestParameters(token, tokenType))
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk());

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByToken(eq(token.getTokenValue()), isNull());

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
		assertThat(accessToken.isInvalidated()).isTrue();
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = updatedAuthorization.getRefreshToken();
		assertThat(refreshToken.isInvalidated()).isFalse();
	}

	private static MultiValueMap<String, String> getTokenRevocationRequestParameters(AbstractOAuth2Token token, OAuth2TokenType tokenType) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames2.TOKEN, token.getTokenValue());
		parameters.set(OAuth2ParameterNames2.TOKEN_TYPE_HINT, tokenType.getValue());
		return parameters;
	}

	private static String encodeBasicAuth(String clientId, String secret) throws Exception {
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return new String(encodedBytes, StandardCharsets.UTF_8);
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

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationCustomEndpoints extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return providerSettings;
		}
	}

}
