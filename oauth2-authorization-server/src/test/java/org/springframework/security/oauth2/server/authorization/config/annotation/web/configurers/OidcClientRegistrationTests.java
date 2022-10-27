/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.test.SpringTestRule;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OpenID Connect Dynamic Client Registration 1.0.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 */
public class OidcClientRegistrationTests {
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";
	private static final String DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI = "/connect/register";
	private static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();
	private static final HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter =
			new OidcClientRegistrationHttpMessageConverter();
	private static EmbeddedDatabase db;
	private static JWKSource<SecurityContext> jwkSource;
	private static JWKSet clientJwkSet;
	private static JwtEncoder jwtClientAssertionEncoder;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JdbcOperations jdbcOperations;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	private static AuthenticationConverter authenticationConverter;

	private static Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer;

	private static AuthenticationProvider authenticationProvider;

	private static Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer;

	private static AuthenticationSuccessHandler authenticationSuccessHandler;

	private static AuthenticationFailureHandler authenticationFailureHandler;

	private MockWebServer server;
	private String clientJwkSetUrl;


	@BeforeClass
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		clientJwkSet = new JWKSet(TestJwks.generateRsaJwk().build());
		jwtClientAssertionEncoder = new NimbusJwtEncoder((jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet));
		db = new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		authenticationConverter = mock(AuthenticationConverter.class);
		authenticationConvertersConsumer = mock(Consumer.class);
		authenticationProvider = mock(AuthenticationProvider.class);
		authenticationProvidersConsumer = mock(Consumer.class);
		authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
	}

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.clientJwkSetUrl = this.server.url("/jwks").toString();
		// @formatter:off
		MockResponse response = new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(clientJwkSet.toString());
		// @formatter:on
		this.server.enqueue(response);
		when(authenticationProvider.supports(OidcClientRegistrationAuthenticationToken.class)).thenReturn(true);
	}

	@After
	public void tearDown() throws Exception {
		this.server.shutdown();
		jdbcOperations.update("truncate table oauth2_authorization");
		jdbcOperations.update("truncate table oauth2_registered_client");
		reset(authenticationConverter);
		reset(authenticationConvertersConsumer);
		reset(authenticationProvider);
		reset(authenticationProvidersConsumer);
		reset(authenticationSuccessHandler);
		reset(authenticationFailureHandler);
	}

	@AfterClass
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenClientRegistrationRequestAuthorizedThenClientRegistrationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		assertThat(clientRegistrationResponse.getClientId()).isNotNull();
		assertThat(clientRegistrationResponse.getClientIdIssuedAt()).isNotNull();
		assertThat(clientRegistrationResponse.getClientSecret()).isNotNull();
		assertThat(clientRegistrationResponse.getClientSecretExpiresAt()).isNull();
		assertThat(clientRegistrationResponse.getClientName()).isEqualTo(clientRegistration.getClientName());
		assertThat(clientRegistrationResponse.getRedirectUris())
				.containsExactlyInAnyOrderElementsOf(clientRegistration.getRedirectUris());
		assertThat(clientRegistrationResponse.getGrantTypes())
				.containsExactlyInAnyOrderElementsOf(clientRegistration.getGrantTypes());
		assertThat(clientRegistrationResponse.getResponseTypes())
				.containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistrationResponse.getScopes())
				.containsExactlyInAnyOrderElementsOf(clientRegistration.getScopes());
		assertThat(clientRegistrationResponse.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(clientRegistrationResponse.getIdTokenSignedResponseAlgorithm())
				.isEqualTo(SignatureAlgorithm.RS256.getName());
		assertThat(clientRegistrationResponse.getRegistrationClientUrl()).isNotNull();
		assertThat(clientRegistrationResponse.getRegistrationAccessToken()).isNotEmpty();
	}

	@Test
	public void requestWhenClientConfigurationRequestAuthorizedThenClientRegistrationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setBearerAuth(clientRegistrationResponse.getRegistrationAccessToken());

		MvcResult mvcResult = this.mvc.perform(get(clientRegistrationResponse.getRegistrationClientUrl().toURI())
				.headers(httpHeaders))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
				.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
				.andReturn();

		OidcClientRegistration clientConfigurationResponse = readClientRegistrationResponse(mvcResult.getResponse());

		assertThat(clientConfigurationResponse.getClientId()).isEqualTo(clientRegistrationResponse.getClientId());
		assertThat(clientConfigurationResponse.getClientIdIssuedAt()).isEqualTo(clientRegistrationResponse.getClientIdIssuedAt());
		assertThat(clientConfigurationResponse.getClientSecret()).isEqualTo(clientRegistrationResponse.getClientSecret());
		assertThat(clientConfigurationResponse.getClientSecretExpiresAt()).isEqualTo(clientRegistrationResponse.getClientSecretExpiresAt());
		assertThat(clientConfigurationResponse.getClientName()).isEqualTo(clientRegistrationResponse.getClientName());
		assertThat(clientConfigurationResponse.getRedirectUris())
				.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getRedirectUris());
		assertThat(clientConfigurationResponse.getGrantTypes())
				.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getGrantTypes());
		assertThat(clientConfigurationResponse.getResponseTypes())
				.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getResponseTypes());
		assertThat(clientConfigurationResponse.getScopes())
				.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getScopes());
		assertThat(clientConfigurationResponse.getTokenEndpointAuthenticationMethod())
				.isEqualTo(clientRegistrationResponse.getTokenEndpointAuthenticationMethod());
		assertThat(clientConfigurationResponse.getIdTokenSignedResponseAlgorithm())
				.isEqualTo(clientRegistrationResponse.getIdTokenSignedResponseAlgorithm());
		assertThat(clientConfigurationResponse.getRegistrationClientUrl())
				.isEqualTo(clientRegistrationResponse.getRegistrationClientUrl());
		assertThat(clientConfigurationResponse.getRegistrationAccessToken()).isNull();
	}

	@Test
	public void requestWhenUserInfoEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(CustomClientRegistrationConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		doAnswer(invocation -> {
			HttpServletResponse response = invocation.getArgument(1, HttpServletResponse.class);
			ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
			httpResponse.setStatusCode(HttpStatus.CREATED);
			new OidcClientRegistrationHttpMessageConverter().write(clientRegistration, null, httpResponse);
			return null;
		}).when(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), any());

		registerClient(clientRegistration);

		verify(authenticationConverter).convert(any());
		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor
				.forClass(List.class);
		verify(authenticationConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).hasSize(2).contains(authenticationConverter);

		verify(authenticationProvider).authenticate(any());
		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor
				.forClass(List.class);
		verify(authenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders).hasSize(3)
				.allMatch(provider -> provider == authenticationProvider
						|| provider instanceof OidcClientRegistrationAuthenticationProvider
						|| provider instanceof OidcClientConfigurationAuthenticationProvider);

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), any());
		verifyNoInteractions(authenticationFailureHandler);
	}

	@Test
	public void requestWhenUserInfoEndpointCustomizedAndErrorThenUsed() throws Exception {
		this.spring.register(CustomClientRegistrationConfiguration.class).autowire();

		when(authenticationProvider.authenticate(any())).thenThrow(new OAuth2AuthenticationException("error"));

		this.mvc.perform(get(DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI)
				.param(OAuth2ParameterNames.CLIENT_ID, "invalid").with(jwt()));

		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), any());
		verifyNoInteractions(authenticationSuccessHandler);
	}

	private OidcClientRegistration registerClient(OidcClientRegistration clientRegistration) throws Exception {
		// ***** (1) Obtain the "initial" access token used for registering the client

		String clientRegistrationScope = "client.create";
		// @formatter:off
		RegisteredClient clientRegistrar = RegisteredClient.withId("client-registrar-1")
				.clientId("client-registrar-1")
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope(clientRegistrationScope)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl(this.clientJwkSetUrl)
								.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
								.build()
				)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(clientRegistrar);

		// @formatter:off
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.build();
		JwtClaimsSet jwtClaimsSet = jwtClientAssertionClaims(clientRegistrar)
				.build();
		// @formatter:on
		Jwt jwtAssertion = jwtClientAssertionEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, clientRegistrationScope)
				.param(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
				.param(OAuth2ParameterNames.CLIENT_ASSERTION, jwtAssertion.getTokenValue())
				.param(OAuth2ParameterNames.CLIENT_ID, clientRegistrar.getClientId()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").value(clientRegistrationScope))
				.andReturn();

		OAuth2AccessToken accessToken = readAccessTokenResponse(mvcResult.getResponse()).getAccessToken();

		// ***** (2) Register the client

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setBearerAuth(accessToken.getTokenValue());

		// Register the client
		mvcResult = this.mvc.perform(post(DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI)
				.headers(httpHeaders)
				.contentType(MediaType.APPLICATION_JSON)
				.content(getClientRegistrationRequestContent(clientRegistration)))
				.andExpect(status().isCreated())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
				.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
				.andReturn();

		return readClientRegistrationResponse(mvcResult.getResponse());
	}

	private JwtClaimsSet.Builder jwtClientAssertionClaims(RegisteredClient registeredClient) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return JwtClaimsSet.builder()
				.issuer(registeredClient.getClientId())
				.subject(registeredClient.getClientId())
				.audience(Collections.singletonList(asUrl(this.authorizationServerSettings.getIssuer(), this.authorizationServerSettings.getTokenEndpoint())))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt);
	}

	private static String asUrl(String uri, String path) {
		return UriComponentsBuilder.fromUriString(uri).path(path).build().toUriString();
	}

	private static OAuth2AccessTokenResponse readAccessTokenResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

	private static byte[] getClientRegistrationRequestContent(OidcClientRegistration clientRegistration) throws Exception {
		MockHttpOutputMessage httpRequest = new MockHttpOutputMessage();
		clientRegistrationHttpMessageConverter.write(clientRegistration, null, httpRequest);
		return httpRequest.getBodyAsBytes();
	}

	private static OidcClientRegistration readClientRegistrationResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return clientRegistrationHttpMessageConverter.read(OidcClientRegistration.class, httpResponse);
	}

	@EnableWebSecurity
	static class CustomClientRegistrationConfiguration extends AuthorizationServerConfiguration {

		@Bean
		@Override
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
			authorizationServerConfigurer.oidc(oidc -> oidc.clientRegistrationEndpoint(
					clientRegistration -> clientRegistration.clientRegistrationRequestConverter(authenticationConverter)
							.clientRegistrationRequestConverters(authenticationConvertersConsumer)
							.authenticationProvider(authenticationProvider)
							.authenticationProviders(authenticationProvidersConsumer)
							.clientRegistrationResponseHandler(authenticationSuccessHandler)
							.errorResponseHandler(authenticationFailureHandler)));
			RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

			http.requestMatcher(endpointsMatcher)
					.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
					.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
					.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt).apply(authorizationServerConfigurer);
			return http.build();

		}

	}

	@EnableWebSecurity
	static class AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer();
			authorizationServerConfigurer
					.oidc(oidc ->
							oidc.clientRegistrationEndpoint(Customizer.withDefaults()));
			RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

			http
					.requestMatcher(endpointsMatcher)
					.authorizeRequests(authorizeRequests ->
							authorizeRequests.anyRequest().authenticated()
					)
					.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
					.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
					.apply(authorizationServerConfigurer);
			return http.build();
		}
		// @formatter:on

		@Bean
		RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
			RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
			RegisteredClientParametersMapper registeredClientParametersMapper = new RegisteredClientParametersMapper();
			JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcOperations);
			registeredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper);
			registeredClientRepository.save(registeredClient);
			return registeredClientRepository;
		}

		@Bean
		OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
			return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
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
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder()
					.issuer("https://auth-server:9000")
					.build();
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

}
