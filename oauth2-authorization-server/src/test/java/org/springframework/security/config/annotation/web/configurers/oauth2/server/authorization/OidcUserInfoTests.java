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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.springframework.test.web.servlet.ResultMatcher.matchAll;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OpenID Connect 1.0 UserInfo endpoint.
 *
 * @author Steve Riesenberg
 */
public class OidcUserInfoTests {
	private static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";
	private static SecurityContextRepository securityContextRepository;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@BeforeClass
	public static void init() {
		securityContextRepository = spy(new HttpSessionSecurityContextRepository());
	}

	@Before
	public void setup() {
		reset(securityContextRepository);
	}

	@Test
	public void requestWhenUserInfoRequestGetThenUserInfoResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpect(userInfoResponse());
		// @formatter:on
	}

	@Test
	public void requestWhenUserInfoRequestPostThenUserInfoResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(post(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpect(userInfoResponse());
		// @formatter:on
	}

	@Test
	public void requestWhenSignedJwtAndCustomUserInfoMapperThenMapJwtClaimsToUserInfoResponse() throws Exception {
		this.spring.register(CustomUserInfoConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpect(userInfoResponse());
		// @formatter:on
	}

	// gh-482
	@Test
	public void requestWhenUserInfoRequestThenBearerTokenAuthenticationNotPersisted() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithSecurityContextRepository.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpect(userInfoResponse())
				.andReturn();
		// @formatter:on

		org.springframework.security.core.context.SecurityContext securityContext =
				securityContextRepository.loadContext(mvcResult.getRequest()).get();
		assertThat(securityContext.getAuthentication()).isNull();
	}

	private static ResultMatcher userInfoResponse() {
		// @formatter:off
		return matchAll(
				jsonPath("sub").value("user1"),
				jsonPath("name").value("First Last"),
				jsonPath("given_name").value("First"),
				jsonPath("family_name").value("Last"),
				jsonPath("middle_name").value("Middle"),
				jsonPath("nickname").value("User"),
				jsonPath("preferred_username").value("user"),
				jsonPath("profile").value("https://example.com/user1"),
				jsonPath("picture").value("https://example.com/user1.jpg"),
				jsonPath("website").value("https://example.com"),
				jsonPath("email").value("user1@example.com"),
				jsonPath("email_verified").value("true"),
				jsonPath("gender").value("female"),
				jsonPath("birthdate").value("1970-01-01"),
				jsonPath("zoneinfo").value("Europe/Paris"),
				jsonPath("locale").value("en-US"),
				jsonPath("phone_number").value("+1 (604) 555-1234;ext=5678"),
				jsonPath("phone_number_verified").value("false"),
				jsonPath("address.formatted").value("Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"),
				jsonPath("updated_at").value("1970-01-01T00:00:00Z")
		);
		// @formatter:on
	}

	private OAuth2Authorization createAuthorization() {
		JwsHeader headers = JwsHeader.with(SignatureAlgorithm.RS256).build();
		// @formatter:off
		JwtClaimsSet claimSet = JwtClaimsSet.builder()
				.claims(claims -> claims.putAll(createUserInfo().getClaims()))
				.build();
		// @formatter:on
		Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(headers, claimSet));

		Instant now = Instant.now();
		Set<String> scopes = new HashSet<>(Arrays.asList(
				OidcScopes.OPENID, OidcScopes.ADDRESS, OidcScopes.EMAIL, OidcScopes.PHONE, OidcScopes.PROFILE));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(), now, now.plusSeconds(300), scopes);
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
				.claims(claims -> claims.putAll(createUserInfo().getClaims()))
				.build();

		return TestOAuth2Authorizations.authorization()
				.accessToken(accessToken)
				.token(idToken)
				.build();
	}

	private static OidcUserInfo createUserInfo() {
		// @formatter:off
		return OidcUserInfo.builder()
				.subject("user1")
				.name("First Last")
				.givenName("First")
				.familyName("Last")
				.middleName("Middle")
				.nickname("User")
				.preferredUsername("user")
				.profile("https://example.com/user1")
				.picture("https://example.com/user1.jpg")
				.website("https://example.com")
				.email("user1@example.com")
				.emailVerified(true)
				.gender("female")
				.birthdate("1970-01-01")
				.zoneinfo("Europe/Paris")
				.locale("en-US")
				.phoneNumber("+1 (604) 555-1234;ext=5678")
				.phoneNumberVerified("false")
				.claim("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
				.updatedAt("1970-01-01T00:00:00Z")
				.build();
		// @formatter:on
	}

	@EnableWebSecurity
	static class CustomUserInfoConfiguration extends AuthorizationServerConfiguration {

		@Bean
		@Override
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer<>();
			RequestMatcher endpointsMatcher = authorizationServerConfigurer
					.getEndpointsMatcher();

			// Custom User Info Mapper that retrieves claims from a signed JWT
			Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = context -> {
				OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
				JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();

				return new OidcUserInfo(principal.getToken().getClaims());
			};

			// @formatter:off
			http
				.requestMatcher(endpointsMatcher)
				.authorizeRequests(authorizeRequests ->
					authorizeRequests.anyRequest().authenticated()
				)
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.apply(authorizationServerConfigurer)
					.oidc(oidc -> oidc
						.userInfoEndpoint(userInfo -> userInfo
							.userInfoMapper(userInfoMapper)
						)
					);
			// @formatter:on

			return http.build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithSecurityContextRepository extends AuthorizationServerConfiguration {

		@Bean
		@Override
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer<>();
			RequestMatcher endpointsMatcher = authorizationServerConfigurer
					.getEndpointsMatcher();

			// @formatter:off
			http
				.requestMatcher(endpointsMatcher)
				.authorizeRequests(authorizeRequests ->
					authorizeRequests.anyRequest().authenticated()
				)
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.securityContext(securityContext ->
					securityContext.securityContextRepository(securityContextRepository))
				.apply(authorizationServerConfigurer);
			// @formatter:on

			return http.build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfiguration {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer<>();
			RequestMatcher endpointsMatcher = authorizationServerConfigurer
					.getEndpointsMatcher();

			// @formatter:off
			http
				.requestMatcher(endpointsMatcher)
				.authorizeRequests(authorizeRequests ->
					authorizeRequests.anyRequest().authenticated()
				)
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.apply(authorizationServerConfigurer);
			// @formatter:on

			return http.build();
		}

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
			return new InMemoryRegisteredClientRepository(registeredClient);
		}

		@Bean
		OAuth2AuthorizationService authorizationService() {
			return new InMemoryOAuth2AuthorizationService();
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return new ImmutableJWKSet<>(new JWKSet(TestJwks.DEFAULT_RSA_JWK));
		}

		@Bean
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
			return new NimbusJwtEncoder(jwkSource);
		}

		@Bean
		ProviderSettings providerSettings() {
			return ProviderSettings.builder()
					.issuer("https://auth-server:9000")
					.build();
		}

	}

}
