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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.text.MessageFormat;
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
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

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
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static JWKSource<SecurityContext> jwkSource;
	private static NimbusJwsEncoder jwtEncoder;
	private static ProviderSettings providerSettings;
	private static HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();
	private static String consentPage = "/custom-consent";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JwtDecoder jwtDecoder;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authorizationService = mock(OAuth2AuthorizationService.class);
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		jwtEncoder = new NimbusJwsEncoder(jwkSource);
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
	public void requestWhenAuthorizationRequestNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		this.mvc.perform(get(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient)))
				.andExpect(status().isUnauthorized())
				.andReturn();

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
				eq(authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()),
				eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		OAuth2AccessTokenResponse accessTokenResponse = assertTokenRequestReturnsAccessTokenResponse(
				registeredClient, authorization, OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI);

		// Assert user authorities was propagated as claim in JWT
		Jwt jwt = this.jwtDecoder.decode(accessTokenResponse.getAccessToken().getTokenValue());
		List<String> authoritiesClaim = jwt.getClaim(AUTHORITIES_CLAIM);
		Authentication principal = authorization.getAttribute(Principal.class.getName());
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
				eq(authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()),
				eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		assertTokenRequestReturnsAccessTokenResponse(
				registeredClient, authorization, providerSettings.tokenEndpoint());
	}

	private OAuth2AccessTokenResponse assertTokenRequestReturnsAccessTokenResponse(RegisteredClient registeredClient,
			OAuth2Authorization authorization, String tokenEndpointUri) throws Exception {
		MvcResult mvcResult = this.mvc.perform(post(tokenEndpointUri)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
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
				eq(authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()),
				eq(AUTHORIZATION_CODE_TOKEN_TYPE));
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
				eq(authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()),
				eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.param(PkceParameterNames.CODE_VERIFIER, S256_CODE_VERIFIER))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
				.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").doesNotExist())
				.andExpect(jsonPath("$.scope").isNotEmpty());

		verify(registeredClientRepository, times(2)).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService, times(2)).findByToken(
				eq(authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()),
				eq(AUTHORIZATION_CODE_TOKEN_TYPE));
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
				eq(authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()),
				eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorization);

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)));
	}

	@Test
	public void requestWhenRequiresConsentThenDisplaysConsentPage() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add("message.read");
					scopes.add("message.write");
				})
				.clientSettings(settings -> settings.requireUserConsent(true))
				.build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		String consentPage = this.mvc.perform(get(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
				.andExpect(status().is2xxSuccessful())
				.andReturn()
				.getResponse()
				.getContentAsString();


		assertThat(consentPage).contains("Consent required");
		assertThat(consentPage).contains(scopeCheckbox("message.read"));
		assertThat(consentPage).contains(scopeCheckbox("message.write"));
	}

	@Test
	public void requestWhenConsentRequestReturnAccessTokenResponse() throws Exception {
		final String stateParameter = "consent-state";
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add("message.read");
					scopes.add("message.write");
				})
				.clientSettings(settings -> settings.requireUserConsent(true))
				.build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization stateTokenAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName("user")
				.build();

		when(authorizationService.findByToken(
				eq(stateParameter),
				eq(new OAuth2TokenType(OAuth2ParameterNames.STATE))))
				.thenReturn(stateTokenAuthorization);

		MvcResult mvcResult = this.mvc.perform(post(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.param(OAuth2ParameterNames.SCOPE, "message.read")
				.param(OAuth2ParameterNames.SCOPE, "message.write")
				.param(OAuth2ParameterNames.STATE, stateParameter)
				.param("consent_action", "approve")
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();

		assertThat(mvcResult.getResponse().getRedirectedUrl()).matches("https://example.com\\?code=.{15,}&state=state");
		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorizationCodeAuthorization = authorizationCaptor.getValue();
		when(authorizationService.findByToken(
				eq(authorizationCodeAuthorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue()),
				eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
				.thenReturn(authorizationCodeAuthorization);

		this.mvc.perform(post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
				.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andReturn();
	}

	@Test
	public void requestWhenCustomConsentPageConfiguredThenRedirect() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomConsentPage.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add("message.read");
					scopes.add("message.write");
				})
				.clientSettings(settings -> settings.requireUserConsent(true))
				.build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();

		String locationHeader = URLDecoder.decode(mvcResult.getResponse().getRedirectedUrl(), StandardCharsets.UTF_8.name());
		UriComponents redirectedUrl = UriComponentsBuilder.fromUriString(locationHeader).build();
		MultiValueMap<String, String> redirectQueryParams = redirectedUrl.getQueryParams();

		assertThat(redirectedUrl.getPath()).isEqualTo(consentPage);
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("message.read message.write");
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.CLIENT_ID)).isEqualTo(registeredClient.getClientId());

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.STATE)).isEqualTo(authorization.getAttribute(OAuth2ParameterNames.STATE));
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
		parameters.set(OAuth2ParameterNames.CODE, authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		return parameters;
	}

	private static String getAuthorizationHeader(RegisteredClient registeredClient) throws Exception {
		String clientId = registeredClient.getClientId();
		String secret = registeredClient.getClientSecret();
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return "Basic " + new String(encodedBytes, StandardCharsets.UTF_8);
	}

	private static String scopeCheckbox(String scope) {
		return MessageFormat.format(
				"<input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"{0}\" id=\"{0}\" checked>",
				scope
		);
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
						OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
					Authentication principal = context.getPrincipal();
					Set<String> authorities = principal.getAuthorities().stream()
							.map(GrantedAuthority::getAuthority)
							.collect(Collectors.toSet());
					context.getClaims().claim(AUTHORITIES_CLAIM, authorities);
				}
			};
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
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

	@EnableWebSecurity
	static class AuthorizationServerConfigurationCustomConsentPage extends AuthorizationServerConfiguration {
		// @formatter:off
		@Bean
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer<>();
			authorizationServerConfigurer.consentPage(consentPage);
			RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

			http
					.requestMatcher(endpointsMatcher)
					.authorizeRequests(authorizeRequests ->
							authorizeRequests.anyRequest().authenticated()
					)
					.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
					.apply(authorizationServerConfigurer);
			return http.build();
		}
		// @formatter:on
	}
}
