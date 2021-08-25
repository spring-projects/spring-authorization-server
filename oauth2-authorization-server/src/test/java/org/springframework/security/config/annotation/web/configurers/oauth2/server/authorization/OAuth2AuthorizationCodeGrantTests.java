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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
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
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.jackson2.TestingAuthenticationTokenMixin;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
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
import static org.mockito.Mockito.verify;
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
 * @author Dmitriy Dubson
 */
public class OAuth2AuthorizationCodeGrantTests {
	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";
	// See RFC 7636: Appendix B.  Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private static final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private static final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private static final String AUTHORITIES_CLAIM = "authorities";
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private static EmbeddedDatabase db;
	private static JWKSource<SecurityContext> jwkSource;
	private static NimbusJwsEncoder jwtEncoder;
	private static ProviderSettings providerSettings;
	private static HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();
	private static AuthenticationConverter authorizationRequestConverter;
	private static AuthenticationProvider authorizationRequestAuthenticationProvider;
	private static AuthenticationSuccessHandler authorizationResponseHandler;
	private static AuthenticationFailureHandler authorizationErrorResponseHandler;
	private static String consentPage = "/oauth2/consent";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JdbcOperations jdbcOperations;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@Autowired
	private JwtDecoder jwtDecoder;

	@BeforeClass
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		jwtEncoder = new NimbusJwsEncoder(jwkSource);
		providerSettings = ProviderSettings.builder()
				.authorizationEndpoint("/test/authorize")
				.tokenEndpoint("/test/token")
				.build();
		authorizationRequestConverter = mock(AuthenticationConverter.class);
		authorizationRequestAuthenticationProvider = mock(AuthenticationProvider.class);
		authorizationResponseHandler = mock(AuthenticationSuccessHandler.class);
		authorizationErrorResponseHandler = mock(AuthenticationFailureHandler.class);
		db = new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
	}

	@After
	public void tearDown() {
		jdbcOperations.update("truncate table oauth2_authorization");
		jdbcOperations.update("truncate table oauth2_authorization_consent");
		jdbcOperations.update("truncate table oauth2_registered_client");
	}

	@AfterClass
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenAuthorizationRequestNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		this.mvc.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient)))
				.andExpect(status().isUnauthorized())
				.andReturn();
	}

	@Test
	public void requestWhenRegisteredClientMissingThenBadRequest() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		this.mvc.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient)))
				.andExpect(status().isBadRequest())
				.andReturn();
	}

	@Test
	public void requestWhenAuthorizationRequestAuthenticatedThenRedirectToClient() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		assertAuthorizationRequestRedirectsToClient(DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	@Test
	public void requestWhenAuthorizationRequestCustomEndpointThenRedirectToClient() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomEndpoints.class).autowire();

		assertAuthorizationRequestRedirectsToClient(providerSettings.getAuthorizationEndpoint());
	}

	private void assertAuthorizationRequestRedirectsToClient(String authorizationEndpointUri) throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(authorizationEndpointUri)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("https://example.com\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode, AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isNotNull();
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	@Test
	public void requestWhenTokenRequestValidThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		OAuth2AccessTokenResponse accessTokenResponse = assertTokenRequestReturnsAccessTokenResponse(
				registeredClient, authorization, DEFAULT_TOKEN_ENDPOINT_URI);

		// Assert user authorities was propagated as claim in JWT
		Jwt jwt = this.jwtDecoder.decode(accessTokenResponse.getAccessToken().getTokenValue());
		List<String> authoritiesClaim = jwt.getClaim(AUTHORITIES_CLAIM);
		Authentication principal = authorization.getAttribute(Principal.class.getName());
		Set<String> userAuthorities = new HashSet<>();
		for (GrantedAuthority authority : principal.getAuthorities()) {
			userAuthorities.add(authority.getAuthority());
		}

		assertThat(authoritiesClaim).containsExactlyInAnyOrderElementsOf(userAuthorities);
	}

	@Test
	public void requestWhenTokenRequestCustomEndpointThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomEndpoints.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		assertTokenRequestReturnsAccessTokenResponse(
				registeredClient, authorization, providerSettings.getTokenEndpoint());
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

		OAuth2Authorization accessTokenAuthorization = this.authorizationService.findById(authorization.getId());
		assertThat(accessTokenAuthorization).isNotNull();
		assertThat(accessTokenAuthorization.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthorization.getRefreshToken()).isNotNull();

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = accessTokenAuthorization.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCodeToken).isNotNull();
		assertThat(authorizationCodeToken.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME)).isEqualTo(true);

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
		return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

	@Test
	public void requestWhenPublicClientWithPkceThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.param(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE)
				.param(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256")
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("https://example.com\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode, AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorizationCodeAuthorization).isNotNull();
		assertThat(authorizationCodeAuthorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
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

		OAuth2Authorization accessTokenAuthorization = this.authorizationService.findById(authorizationCodeAuthorization.getId());
		assertThat(accessTokenAuthorization).isNotNull();
		assertThat(accessTokenAuthorization.getAccessToken()).isNotNull();

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = accessTokenAuthorization.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCodeToken).isNotNull();
		assertThat(authorizationCodeToken.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME)).isEqualTo(true);
	}

	@Test
	public void requestWhenCustomJwtEncoderThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithJwtEncoder.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
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
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		this.registeredClientRepository.save(registeredClient);

		String consentPage = this.mvc.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
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
	public void requestWhenConsentRequestThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add("message.read");
					scopes.add("message.write");
				})
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName("user")
				.build();
		this.authorizationService.save(authorization);

		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.param(OAuth2ParameterNames.SCOPE, "message.read")
				.param(OAuth2ParameterNames.SCOPE, "message.write")
				.param(OAuth2ParameterNames.STATE, "state")
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();

		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("https://example.com\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode, AUTHORIZATION_CODE_TOKEN_TYPE);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
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
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("http://localhost/oauth2/consent\\?scope=.+&client_id=.+&state=.+");

		String locationHeader = URLDecoder.decode(redirectedUrl, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
		MultiValueMap<String, String> redirectQueryParams = uriComponents.getQueryParams();

		assertThat(uriComponents.getPath()).isEqualTo(consentPage);
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("message.read message.write");
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.CLIENT_ID)).isEqualTo(registeredClient.getClientId());

		String state = extractParameterFromRedirectUri(redirectedUrl, "state");
		OAuth2Authorization authorization = this.authorizationService.findByToken(state, STATE_TOKEN_TYPE);
		assertThat(authorization).isNotNull();
	}

	@Test
	public void requestWhenAuthorizationEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomAuthorizationEndpoint.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principalName", "password");
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
				"code", Instant.now(), Instant.now().plus(5, ChronoUnit.MINUTES));
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
						.authorizationUri("https://provider.com/oauth2/authorize")
						.redirectUri(registeredClient.getRedirectUris().iterator().next())
						.scopes(registeredClient.getScopes())
						.state("state")
						.authorizationCode(authorizationCode)
						.build();
		when(authorizationRequestConverter.convert(any())).thenReturn(authorizationCodeRequestAuthenticationResult);
		when(authorizationRequestAuthenticationProvider.supports(eq(OAuth2AuthorizationCodeRequestAuthenticationToken.class))).thenReturn(true);
		when(authorizationRequestAuthenticationProvider.authenticate(any())).thenReturn(authorizationCodeRequestAuthenticationResult);

		this.mvc.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
				.andExpect(status().isOk());

		verify(authorizationRequestConverter).convert(any());
		verify(authorizationRequestAuthenticationProvider).authenticate(eq(authorizationCodeRequestAuthenticationResult));
		verify(authorizationResponseHandler).onAuthenticationSuccess(any(), any(), eq(authorizationCodeRequestAuthenticationResult));
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
		String clientSecret = registeredClient.getClientSecret();
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + clientSecret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return "Basic " + new String(encodedBytes, StandardCharsets.UTF_8);
	}

	private static String scopeCheckbox(String scope) {
		return MessageFormat.format(
				"<input class=\"form-check-input scope-to-accept\" type=\"checkbox\" name=\"scope\" value=\"{0}\" id=\"{0}\">",
				scope
		);
	}

	private String extractParameterFromRedirectUri(String redirectUri, String param) throws UnsupportedEncodingException {
		String locationHeader = URLDecoder.decode(redirectUri, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
		return uriComponents.getQueryParams().getFirst(param);
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
			JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
			authorizationService.setAuthorizationRowMapper(new RowMapper(registeredClientRepository));
			authorizationService.setAuthorizationParametersMapper(new ParametersMapper());
			return authorizationService;
		}

		@Bean
		OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
			return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
		}

		@Bean
		RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations, PasswordEncoder passwordEncoder) {
			JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcOperations);
			RegisteredClientParametersMapper registeredClientParametersMapper = new RegisteredClientParametersMapper();
			registeredClientParametersMapper.setPasswordEncoder(passwordEncoder);
			jdbcRegisteredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper);
			return jdbcRegisteredClientRepository;
		}

		@Bean
		JdbcOperations jdbcOperations() {
			return new JdbcTemplate(db);
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return jwkSource;
		}

		@Bean
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return context -> {
				if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType()) &&
						OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
					Authentication principal = context.getPrincipal();
					Set<String> authorities = new HashSet<>();
					for (GrantedAuthority authority : principal.getAuthorities()) {
						authorities.add(authority.getAuthority());
					}
					context.getClaims().claim(AUTHORITIES_CLAIM, authorities);
				}
			};
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

		static class RowMapper extends JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper {

			RowMapper(RegisteredClientRepository registeredClientRepository) {
				super(registeredClientRepository);
				getObjectMapper().addMixIn(TestingAuthenticationToken.class, TestingAuthenticationTokenMixin.class);
			}

		}

		static class ParametersMapper extends JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper {

			ParametersMapper() {
				super();
				getObjectMapper().addMixIn(TestingAuthenticationToken.class, TestingAuthenticationTokenMixin.class);
			}

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
			authorizationServerConfigurer
					.authorizationEndpoint(authorizationEndpoint ->
							authorizationEndpoint.consentPage(consentPage));
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

	@EnableWebSecurity
	static class AuthorizationServerConfigurationCustomAuthorizationEndpoint extends AuthorizationServerConfiguration {
		// @formatter:off
		@Bean
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer<>();
			authorizationServerConfigurer
					.authorizationEndpoint(authorizationEndpoint ->
							authorizationEndpoint
									.authorizationRequestConverter(authorizationRequestConverter)
									.authenticationProvider(authorizationRequestAuthenticationProvider)
									.authorizationResponseHandler(authorizationResponseHandler)
									.errorResponseHandler(authorizationErrorResponseHandler));
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
