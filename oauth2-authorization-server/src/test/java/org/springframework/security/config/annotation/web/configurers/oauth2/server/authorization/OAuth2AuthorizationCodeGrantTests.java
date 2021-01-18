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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationCodeGrantTests {
	// See RFC 7636: Appendix B.  Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private static final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private static final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private static final String AUTHORITIES_CLAIM = "authorities";

	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static JWKSource<SecurityContext> jwkSource;
	private static NimbusJwsEncoder jwtEncoder;
	private static NimbusJwtDecoder jwtDecoder;
	private static ProviderSettings providerSettings;
	private static HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();

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
		jwtEncoder = new NimbusJwsEncoder(jwkSource);
		jwtDecoder = NimbusJwtDecoder.withPublicKey(TestKeys.DEFAULT_PUBLIC_KEY).build();
		providerSettings = new ProviderSettings()
				.authorizationEndpoint("/test/authorize")
				.tokenEndpoint("/test/token");
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

		assertAuthorizationRequestRedirectsToClient(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	@Test
	public void requestWhenAuthorizationRequestCustomEndpointThenRedirectToClient() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomEndpoints.class).autowire();

		assertAuthorizationRequestRedirectsToClient(providerSettings.authorizationEndpoint());
	}

	private void assertAuthorizationRequestRedirectsToClient(String authorizationEndpointUri) throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(authorizationEndpointUri)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://example.com\\?code=.{15,}&state=state");

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).save(any());
	}

	@Test
	public void requestWhenTokenRequestValidThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(authorizationService.findByToken(
				eq(authorization.getTokens().getToken(OAuth2AuthorizationCode.class).getTokenValue()),
				eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		OAuth2AccessTokenResponse accessTokenResponse = assertTokenRequestReturnsAccessTokenResponse(
				registeredClient, authorization, OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI);

		// Assert user authorities was propagated as claim in JWT
		Jwt jwt = jwtDecoder.decode(accessTokenResponse.getAccessToken().getTokenValue());
		List<String> authoritiesClaim = jwt.getClaim(AUTHORITIES_CLAIM);
		Authentication principal = authorization.getAttribute(OAuth2AuthorizationAttributeNames.PRINCIPAL);
		Set<String> userAuthorities = principal.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toSet());
		assertThat(authoritiesClaim).containsExactlyInAnyOrderElementsOf(userAuthorities);
	}

	@Test
	public void requestWhenTokenRequestCustomEndpointThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomEndpoints.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(authorizationService.findByToken(
				eq(authorization.getTokens().getToken(OAuth2AuthorizationCode.class).getTokenValue()),
				eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		assertTokenRequestReturnsAccessTokenResponse(
				registeredClient, authorization, providerSettings.tokenEndpoint());
	}

	private OAuth2AccessTokenResponse assertTokenRequestReturnsAccessTokenResponse(RegisteredClient registeredClient,
			OAuth2Authorization authorization, String tokenEndpointUri) throws Exception {

		MvcResult mvcResult = this.mvc.perform(post(tokenEndpointUri)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
				.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andReturn();

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByToken(
				eq(authorization.getTokens().getToken(OAuth2AuthorizationCode.class).getTokenValue()),
				eq(TokenType.AUTHORIZATION_CODE));
		verify(authorizationService).save(any());

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
		return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

	@Test
	public void requestWhenPublicClientWithPkceThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.param(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE)
				.param(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256")
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://example.com\\?code=.{15,}&state=state");

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();

		when(authorizationService.findByToken(
				eq(authorization.getTokens().getToken(OAuth2AuthorizationCode.class).getTokenValue()),
				eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.param(PkceParameterNames.CODE_VERIFIER, S256_CODE_VERIFIER))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").doesNotExist())
				.andExpect(jsonPath("$.scope").isNotEmpty());

		verify(registeredClientRepository, times(2)).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService, times(2)).findByToken(
				eq(authorization.getTokens().getToken(OAuth2AuthorizationCode.class).getTokenValue()),
				eq(TokenType.AUTHORIZATION_CODE));
		verify(authorizationService, times(2)).save(any());
	}

	@Test
	public void requestWhenCustomJwtEncoderThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithJwtEncoder.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(authorizationService.findByToken(
				eq(authorization.getTokens().getToken(OAuth2AuthorizationCode.class).getTokenValue()),
				eq(TokenType.AUTHORIZATION_CODE)))
				.thenReturn(authorization);

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())));
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
		parameters.set(OAuth2ParameterNames.CODE, authorization.getTokens().getToken(OAuth2AuthorizationCode.class).getTokenValue());
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

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return jwkSource;
		}

		@Bean
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return context -> {
				if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType()) &&
						TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
					Authentication principal = context.getPrincipal();
					Set<String> authorities = principal.getAuthorities().stream()
							.map(GrantedAuthority::getAuthority)
							.collect(Collectors.toSet());
					context.getClaims().claim(AUTHORITIES_CLAIM, authorities);
				}
			};
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithJwtEncoder extends AuthorizationServerConfiguration {

		@Bean
		JwtEncoder jwtEncoder() {
			return jwtEncoder;
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
