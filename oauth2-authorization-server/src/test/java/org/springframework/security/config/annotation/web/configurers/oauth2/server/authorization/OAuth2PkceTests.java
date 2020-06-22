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

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class OAuth2PkceTests {
	private static RegisteredClientRepository registeredClientRepository;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
	}

	@Test
	public void requestWhenTokenRequestNotAuthenticatedAndPkceParamatersProvidedThenRedirectToClient() throws Exception {
		// See RFC 7636: Appendix B.  Example for the S256 code_challenge_method
		// https://tools.ietf.org/html/rfc7636#appendix-B
		final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
		final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		ClientSettings settings = new ClientSettings();
		RegisteredClient registeredClient = TestRegisteredClients
				.registeredClient()
				.clientSettings(settings.requireProofKey(true))
				.build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.param("code_challenge", S256_CODE_CHALLENGE)
				.param("code_challenge_method", "S256")
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();

		assertThat(mvcResult.getResponse().getRedirectedUrl())
				.doesNotContain("error=")
				.contains("code=");

		String authorizationCode = UriUtils.decode(UriComponentsBuilder.fromHttpUrl(mvcResult.getResponse().getRedirectedUrl())
				.build()
				.getQueryParams()
				.getFirst("code"), "utf-8");

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCode))
				.param("code_verifier", S256_CODE_VERIFIER))
				.andExpect(status().is2xxSuccessful())
				.andExpect(jsonPath("$.access_token").isNotEmpty());
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
			String authorizationCode) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.set(OAuth2ParameterNames.CODE, authorizationCode);
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		return parameters;
	}

	@EnableWebSecurity
	static class AuthorizationServerConfiguration {

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			return registeredClientRepository;
		}

		@Bean
		OAuth2AuthorizationService authorizationService() {
			return new InMemoryOAuth2AuthorizationService();
		}

		@Bean
		KeyManager keyManager() {
			return new StaticKeyGeneratingKeyManager();
		}

		@Bean
		WebSecurityConfigurer<WebSecurity> defaultOAuth2AuthorizationServerSecurity() {
			return new WebSecurityConfigurerAdapter() {
				@Override
				public void configure(HttpSecurity http) throws Exception {
					http
							.authorizeRequests()
							.anyRequest()
							.permitAll()
							.and()
							.csrf()
							.disable()
							.apply(new OAuth2AuthorizationServerConfigurer<>());
				}
			};
		}
	}
}
