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
package org.springframework.security.oauth2.server.authorization.web;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.oauth2.server.authorization.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeGrantTests {
	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authorizationService = mock(OAuth2AuthorizationService.class);
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);
	}

	@Test
	public void requestWhenAuthorizationRequestNotAuthenticatedThenRedirectToLogin() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient)))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).endsWith("/login");

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verifyNoInteractions(authorizationService);
	}

	@Test
	public void requestWhenAuthorizationRequestAuthenticatedThenRedirectToClient() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://example.com\\?code=.{15,}&state=state");

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).save(any());
	}

	@Test
	public void requestWhenTokenRequestValidThenResponseIncludesCacheHeaders() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(authorizationService.findByTokenAndTokenType(
				eq(authorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE)),
				eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret()))
				.with(csrf()))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
				.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")));

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByTokenAndTokenType(
				eq(authorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE)),
				eq(TokenType.AUTHORIZATION_CODE));
		verify(authorizationService).save(any());
	}

	private static MultiValueMap<String, String> getAuthorizationRequestParameters(RegisteredClient registeredClient) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		parameters.set(OAuth2ParameterNames.STATE, "state");
		return parameters;
	}

	private static MultiValueMap<String, String> getTokenRequestParameters(RegisteredClient registeredClient,
			OAuth2Authorization authorization) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.set(OAuth2ParameterNames.CODE, authorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE));
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
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
	}
}
