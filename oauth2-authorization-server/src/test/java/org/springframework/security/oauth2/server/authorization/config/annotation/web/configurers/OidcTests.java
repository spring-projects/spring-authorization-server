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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.jackson2.TestingAuthenticationTokenMixin;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OpenID Connect 1.0.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 */
public class OidcTests {
	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";
	private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";
	private static final String ISSUER_URL = "https://example.com/issuer1";
	private static final String AUTHORITIES_CLAIM = "authorities";
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private static EmbeddedDatabase db;
	private static JWKSource<SecurityContext> jwkSource;
	private static HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();

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

	@Autowired(required = false)
	private OAuth2TokenGenerator<?> tokenGenerator;

	@BeforeClass
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		db = new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
	}

	@After
	public void tearDown() {
		if (jdbcOperations != null) {
			jdbcOperations.update("truncate table oauth2_authorization");
			jdbcOperations.update("truncate table oauth2_registered_client");
		}
	}

	@AfterClass
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenConfigurationRequestAndIssuerSetThenReturnConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithIssuer.class).autowire();

		this.mvc.perform(get(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpect(jsonPath("issuer").value(ISSUER_URL));
	}

	// gh-632
	@Test
	public void requestWhenConfigurationRequestAndUserAuthenticatedThenReturnConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)
				.with(user("user")))
				.andExpect(status().is2xxSuccessful());
	}

	@Test
	public void loadContextWhenIssuerNotValidUrlThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithInvalidIssuerUrl.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerNotValidUriThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithInvalidIssuerUri.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithQueryThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerQuery.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithFragmentThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerFragment.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithQueryAndFragmentThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerQueryAndFragment.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithEmptyQueryThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerEmptyQuery.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithEmptyFragmentThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerEmptyFragment.class).autowire()
		);
	}

	@Test
	public void requestWhenAuthenticationRequestThenTokenResponseIncludesIdToken() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.params(getAuthorizationRequestParameters(registeredClient))
				.with(user("user").roles("A", "B")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("https://example.com\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode, AUTHORIZATION_CODE_TOKEN_TYPE);

		mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
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
				.andExpect(jsonPath("$.id_token").isNotEmpty())
				.andReturn();

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);

		// Assert user authorities was propagated as claim in ID Token
		Jwt idToken = this.jwtDecoder.decode((String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN));
		List<String> authoritiesClaim = idToken.getClaim(AUTHORITIES_CLAIM);
		Authentication principal = authorization.getAttribute(Principal.class.getName());
		Set<String> userAuthorities = new HashSet<>();
		for (GrantedAuthority authority : principal.getAuthorities()) {
			userAuthorities.add(authority.getAuthority());
		}
		assertThat(authoritiesClaim).containsExactlyInAnyOrderElementsOf(userAuthorities);
	}

	@Test
	public void requestWhenCustomTokenGeneratorThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithTokenGenerator.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk());

		verify(this.tokenGenerator, times(3)).generate(any());
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

	private static String encodeBasicAuth(String clientId, String secret) throws Exception {
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return new String(encodedBytes, StandardCharsets.UTF_8);
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
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return context -> {
				if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
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
	static class AuthorizationServerConfigurationWithTokenGenerator extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer<>();
			http.apply(authorizationServerConfigurer);

			authorizationServerConfigurer
					.tokenGenerator(tokenGenerator());

			RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

			http
					.requestMatcher(endpointsMatcher)
					.authorizeRequests(authorizeRequests ->
							authorizeRequests.anyRequest().authenticated()
					)
					.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher));

			return http.build();
		}
		// @formatter:on

		@Bean
		OAuth2TokenGenerator<?> tokenGenerator() {
			JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
			jwtGenerator.setJwtCustomizer(jwtCustomizer());
			OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
			OAuth2TokenGenerator<OAuth2Token> delegatingTokenGenerator =
					new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
			return spy(new OAuth2TokenGenerator<OAuth2Token>() {
				@Override
				public OAuth2Token generate(OAuth2TokenContext context) {
					return delegatingTokenGenerator.generate(context);
				}
			});
		}

	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithIssuer extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer(ISSUER_URL).build();
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithInvalidIssuerUrl extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer("urn:example").build();
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithInvalidIssuerUri extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer("https://not a valid uri").build();
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithIssuerQuery extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer(ISSUER_URL + "?param=value").build();
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithIssuerFragment extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer(ISSUER_URL + "#fragment").build();
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithIssuerQueryAndFragment extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer(ISSUER_URL + "?param=value#fragment").build();
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithIssuerEmptyQuery extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer(ISSUER_URL + "?").build();
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithIssuerEmptyFragment extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder().issuer(ISSUER_URL + "#").build();
		}
	}

}
