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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OpenID Connect 1.0 Client Registration Endpoint.
 *
 * @author Ovidiu Popa
 * @since 0.1.1
 */
public class OidcClientRegistrationTests {
	private static final OidcClientRegistration.Builder OIDC_CLIENT_REGISTRATION = OidcClientRegistration.builder()
			.redirectUri("https://localhost:8080/client")
			.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
			.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
			.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.BASIC.getValue())
			.scope("test");

	private static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();

	private static final OidcClientRegistrationHttpMessageConverter clientRegistrationHttpMessageConverter =
			new OidcClientRegistrationHttpMessageConverter();

	private static final OAuth2TokenType ACCESS_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.ACCESS_TOKEN);

	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static JWKSource<SecurityContext> jwkSource;
	private static NimbusJwtDecoder jwtDecoder;

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
		jwtDecoder = NimbusJwtDecoder.withPublicKey(TestKeys.DEFAULT_PUBLIC_KEY).build();
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);
	}

	@Test
	public void requestWhenAuthenticatedThenResponseIncludesRegisteredClientDetails() throws Exception {
		this.spring.register(AuthorizationServerConfigurationEnabledClientRegistration.class).autowire();
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.scope("client.create").build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		// get access token
		MvcResult mvcResult = this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "client.create")
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").value("client.create"))
				.andReturn();

		//assert get access token
		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();
		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
		String tokenValue = accessTokenResponse.getAccessToken().getTokenValue();

		// prepare register client request
		when(authorizationService.findByToken(
				eq(authorization.getToken(OAuth2AccessToken.class).getToken().getTokenValue()),
				eq(ACCESS_TOKEN_TOKEN_TYPE)))
				.thenReturn(authorization);
		doNothing().when(registeredClientRepository).saveClient(any(RegisteredClient.class));
		mvcResult = this.mvc.perform(post("/connect/register")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenValue)
				.contentType(MediaType.APPLICATION_JSON)
				.content(convertToByteArray(OIDC_CLIENT_REGISTRATION.build())))
				.andExpect(status().isCreated()).andReturn();

		servletResponse = mvcResult.getResponse();
		httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));

		OidcClientRegistration result = clientRegistrationHttpMessageConverter.read(OidcClientRegistration.class, httpResponse);


		assertThat(result).isNotNull();
		assertThat(result.getClaimAsString("client_id")).isNotEmpty();
		assertThat(result.getClaimAsString("client_id_issued_at")).isNotEmpty();
		assertThat(result.getClaimAsString("client_secret")).isNotEmpty();
		assertThat(result.getClaimAsString("client_secret_expires_at")).isNotNull().isEqualTo("0.0");
		assertThat(result.getRedirectUris()).isNotEmpty().containsExactly("https://localhost:8080/client");
		assertThat(result.getResponseTypes()).isNotEmpty().containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(result.getGrantTypes()).isNotEmpty().containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(result.getTokenEndpointAuthenticationMethod()).isNotEmpty().isEqualTo(ClientAuthenticationMethod.BASIC.getValue());
		assertThat(result.getScope()).isNotEmpty().isEqualTo("test");
	}

	private static String encodeBasicAuth(String clientId, String secret) throws Exception {
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return new String(encodedBytes, StandardCharsets.UTF_8);
	}

	private static byte[] convertToByteArray(OidcClientRegistration clientRegistration) throws JsonProcessingException {
		ObjectMapper objectMapper = new ObjectMapper();

		return objectMapper
				.writerFor(Map.class)
				.writeValueAsBytes(clientRegistration.getClaims());
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
	static class AuthorizationServerConfigurationEnabledClientRegistration extends AuthorizationServerConfiguration{

		@Bean
		JwtDecoder jwtDecoder() {
			return jwtDecoder;
		}

		@Bean
		ProviderSettings providerSettings() {
			return new ProviderSettings().isOidClientRegistrationEndpointEnabled(true);
		}
	}
}
