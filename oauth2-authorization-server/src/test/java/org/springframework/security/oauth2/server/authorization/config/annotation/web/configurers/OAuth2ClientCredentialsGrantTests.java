/*
 * Copyright 2020-2023 the original author or authors.
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

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.PublicClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.jackson2.TestingAuthenticationTokenMixin;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContext;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContextExtension;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.JwtClientAssertionAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.PublicClientAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Client Credentials Grant.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2ClientCredentialsGrantTests {
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";
	private static EmbeddedDatabase db;
	private static JWKSource<SecurityContext> jwkSource;
	private static OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;
	private static AuthenticationConverter authenticationConverter;
	private static Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer;
	private static AuthenticationProvider authenticationProvider;
	private static Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer;
	private static AuthenticationSuccessHandler authenticationSuccessHandler;
	private static AuthenticationFailureHandler authenticationFailureHandler;

	public final SpringTestContext spring = new SpringTestContext();

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JdbcOperations jdbcOperations;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@BeforeAll
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		jwtCustomizer = mock(OAuth2TokenCustomizer.class);
		authenticationConverter = mock(AuthenticationConverter.class);
		authenticationConvertersConsumer = mock(Consumer.class);
		authenticationProvider = mock(AuthenticationProvider.class);
		authenticationProvidersConsumer = mock(Consumer.class);
		authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		db = new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
	}

	@SuppressWarnings("unchecked")
	@BeforeEach
	public void setup() {
		reset(jwtCustomizer);
		reset(authenticationConverter);
		reset(authenticationConvertersConsumer);
		reset(authenticationProvider);
		reset(authenticationProvidersConsumer);
		reset(authenticationSuccessHandler);
		reset(authenticationFailureHandler);
	}

	@AfterEach
	public void tearDown() {
		jdbcOperations.update("truncate table oauth2_authorization");
		jdbcOperations.update("truncate table oauth2_registered_client");
	}

	@AfterAll
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenTokenRequestNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(MockMvcRequestBuilders.post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void requestWhenTokenRequestValidThenTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRepository.save(registeredClient);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "scope1 scope2")
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").value("scope1 scope2"));

		verify(jwtCustomizer).customize(any());
	}

	@Test
	public void requestWhenTokenRequestPostsClientCredentialsThenTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRepository.save(registeredClient);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "scope1 scope2")
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.param(OAuth2ParameterNames.CLIENT_SECRET, registeredClient.getClientSecret()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").value("scope1 scope2"));

		verify(jwtCustomizer).customize(any());
	}

	@Test
	public void requestWhenTokenRequestPostsClientCredentialsAndRequiresUpgradingThenClientSecretUpgraded() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomPasswordEncoder.class).autowire();

		String clientSecret = "secret-2";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().clientSecret("{noop}" + clientSecret).build();
		this.registeredClientRepository.save(registeredClient);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
						.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
						.param(OAuth2ParameterNames.SCOPE, "scope1 scope2")
						.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
						.param(OAuth2ParameterNames.CLIENT_SECRET, clientSecret))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").value("scope1 scope2"));

		verify(jwtCustomizer).customize(any());
		RegisteredClient updatedRegisteredClient = this.registeredClientRepository.findByClientId(registeredClient.getClientId());
		assertThat(updatedRegisteredClient.getClientSecret()).startsWith("{bcrypt}");
	}

	@Test
	public void requestWhenTokenEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomTokenEndpoint.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication =
				new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, null, null);
		when(authenticationConverter.convert(any())).thenReturn(clientCredentialsAuthentication);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)));
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
				new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
		when(authenticationProvider.supports(eq(OAuth2ClientCredentialsAuthenticationToken.class))).thenReturn(true);
		when(authenticationProvider.authenticate(any())).thenReturn(accessTokenAuthentication);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk());

		verify(authenticationConverter).convert(any());

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor.forClass(List.class);
		verify(authenticationConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).allMatch((converter) ->
				converter == authenticationConverter ||
						converter instanceof OAuth2AuthorizationCodeAuthenticationConverter ||
						converter instanceof OAuth2RefreshTokenAuthenticationConverter ||
						converter instanceof OAuth2ClientCredentialsAuthenticationConverter ||
						converter instanceof OAuth2DeviceCodeAuthenticationConverter);

		verify(authenticationProvider).authenticate(eq(clientCredentialsAuthentication));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor.forClass(List.class);
		verify(authenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders).allMatch((provider) ->
				provider == authenticationProvider ||
						provider instanceof OAuth2AuthorizationCodeAuthenticationProvider ||
						provider instanceof OAuth2RefreshTokenAuthenticationProvider ||
						provider instanceof OAuth2ClientCredentialsAuthenticationProvider ||
						provider instanceof OAuth2DeviceCodeAuthenticationProvider);

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), eq(accessTokenAuthentication));
	}

	@Test
	public void requestWhenClientAuthenticationCustomizedThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomClientAuthentication.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient, new ClientAuthenticationMethod("custom"), null);
		when(authenticationConverter.convert(any())).thenReturn(clientPrincipal);
		when(authenticationProvider.supports(eq(OAuth2ClientAuthenticationToken.class))).thenReturn(true);
		when(authenticationProvider.authenticate(any())).thenReturn(clientPrincipal);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
				.andExpect(status().isOk());

		verify(authenticationConverter).convert(any());

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor.forClass(List.class);
		verify(authenticationConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).allMatch((converter) ->
				converter == authenticationConverter ||
						converter instanceof JwtClientAssertionAuthenticationConverter ||
						converter instanceof ClientSecretBasicAuthenticationConverter ||
						converter instanceof ClientSecretPostAuthenticationConverter ||
						converter instanceof PublicClientAuthenticationConverter);

		verify(authenticationProvider).authenticate(eq(clientPrincipal));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor.forClass(List.class);
		verify(authenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders).allMatch((provider) ->
				provider == authenticationProvider ||
						provider instanceof JwtClientAssertionAuthenticationProvider ||
						provider instanceof ClientSecretAuthenticationProvider ||
						provider instanceof PublicClientAuthenticationProvider);

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), eq(clientPrincipal));
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
		OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
			JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
			authorizationService.setAuthorizationRowMapper(new RowMapper(registeredClientRepository));
			authorizationService.setAuthorizationParametersMapper(new ParametersMapper());
			return authorizationService;
		}

		@Bean
		RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
			JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcOperations);
			RegisteredClientParametersMapper registeredClientParametersMapper = new RegisteredClientParametersMapper();
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
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return jwtCustomizer;
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
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationCustomTokenEndpoint extends AuthorizationServerConfiguration {
		// @formatter:off
		@Bean
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer();
			authorizationServerConfigurer
					.tokenEndpoint(tokenEndpoint ->
							tokenEndpoint
									.accessTokenRequestConverter(authenticationConverter)
									.accessTokenRequestConverters(authenticationConvertersConsumer)
									.authenticationProvider(authenticationProvider)
									.authenticationProviders(authenticationProvidersConsumer)
									.accessTokenResponseHandler(authenticationSuccessHandler)
									.errorResponseHandler(authenticationFailureHandler));
			RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

			http
					.securityMatcher(endpointsMatcher)
					.authorizeHttpRequests(authorize ->
							authorize.anyRequest().authenticated()
					)
					.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
					.apply(authorizationServerConfigurer);
			return http.build();
		}
		// @formatter:on
	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationCustomPasswordEncoder extends AuthorizationServerConfiguration {
		@Override
		PasswordEncoder passwordEncoder() {
			return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		}
	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationCustomClientAuthentication extends AuthorizationServerConfiguration {
		// @formatter:off
		@Bean
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			authenticationSuccessHandler = spy(authenticationSuccessHandler());

			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer();
			authorizationServerConfigurer
					.clientAuthentication(clientAuthentication ->
							clientAuthentication
									.authenticationConverter(authenticationConverter)
									.authenticationConverters(authenticationConvertersConsumer)
									.authenticationProvider(authenticationProvider)
									.authenticationProviders(authenticationProvidersConsumer)
									.authenticationSuccessHandler(authenticationSuccessHandler)
									.errorResponseHandler(authenticationFailureHandler));
			RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

			http
					.securityMatcher(endpointsMatcher)
					.authorizeHttpRequests(authorize ->
							authorize.anyRequest().authenticated()
					)
					.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
					.apply(authorizationServerConfigurer);
			return http.build();
		}
		// @formatter:on

		private AuthenticationSuccessHandler authenticationSuccessHandler() {
			return new AuthenticationSuccessHandler() {
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
					org.springframework.security.core.context.SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
					securityContext.setAuthentication(authentication);
					SecurityContextHolder.setContext(securityContext);
				}
			};
		}

	}

}
