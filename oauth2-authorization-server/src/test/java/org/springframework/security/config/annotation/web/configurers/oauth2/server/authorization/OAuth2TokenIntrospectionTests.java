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

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.core.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Token Introspection endpoint.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 */
public class OAuth2TokenIntrospectionTests {
	private static JWKSource<SecurityContext> jwkSource;
	private static ProviderSettings providerSettings;
	private final HttpMessageConverter<OAuth2TokenIntrospection> tokenIntrospectionHttpResponseConverter =
			new OAuth2TokenIntrospectionHttpMessageConverter();

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@BeforeClass
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		providerSettings = new ProviderSettings().tokenIntrospectionEndpoint("/test/introspect");
	}

	@Test
	public void requestWhenIntrospectValidAccessTokenThenActive() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient introspectRegisteredClient = TestRegisteredClients.registeredClient2()
				.clientSecret("secret-2").build();
		this.registeredClientRepository.save(introspectRegisteredClient);

		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient().build();
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "access-token", issuedAt, expiresAt,
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		JwtClaimsSet tokenClaims = TestJwtClaimsSets.jwtClaimsSet().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(authorizedRegisteredClient, accessToken, tokenClaims.getClaims())
				.build();
		this.registeredClientRepository.save(authorizedRegisteredClient);
		this.authorizationService.save(authorization);

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(providerSettings.tokenIntrospectionEndpoint())
				.params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
				.with(httpBasic(introspectRegisteredClient.getClientId(), introspectRegisteredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on

		OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);
		assertThat(tokenIntrospectionResponse.isActive()).isTrue();
		assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo(authorizedRegisteredClient.getClientId());
		assertThat(tokenIntrospectionResponse.getUsername()).isNull();
		assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(
				accessToken.getIssuedAt().minusSeconds(1), accessToken.getIssuedAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(
				accessToken.getExpiresAt().minusSeconds(1), accessToken.getExpiresAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getScope()).containsExactlyInAnyOrderElementsOf(accessToken.getScopes());
		assertThat(tokenIntrospectionResponse.getTokenType()).isEqualTo(accessToken.getTokenType().getValue());
		assertThat(tokenIntrospectionResponse.getNotBefore()).isBetween(
				tokenClaims.getNotBefore().minusSeconds(1), tokenClaims.getNotBefore().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getSubject()).isEqualTo(tokenClaims.getSubject());
		assertThat(tokenIntrospectionResponse.getAudience()).containsExactlyInAnyOrderElementsOf(tokenClaims.getAudience());
		assertThat(tokenIntrospectionResponse.getIssuer()).isEqualTo(tokenClaims.getIssuer());
		assertThat(tokenIntrospectionResponse.getId()).isEqualTo(tokenClaims.getId());
	}

	@Test
	public void requestWhenIntrospectValidRefreshTokenThenActive() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient introspectRegisteredClient = TestRegisteredClients.registeredClient2()
				.clientSecret("secret-2").build();
		this.registeredClientRepository.save(introspectRegisteredClient);

		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(authorizedRegisteredClient).build();
		OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
		this.registeredClientRepository.save(authorizedRegisteredClient);
		this.authorizationService.save(authorization);

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(providerSettings.tokenIntrospectionEndpoint())
				.params(getTokenIntrospectionRequestParameters(refreshToken, OAuth2TokenType.REFRESH_TOKEN))
				.with(httpBasic(introspectRegisteredClient.getClientId(), introspectRegisteredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on

		OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);
		assertThat(tokenIntrospectionResponse.isActive()).isTrue();
		assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo(authorizedRegisteredClient.getClientId());
		assertThat(tokenIntrospectionResponse.getUsername()).isNull();
		assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(
				refreshToken.getIssuedAt().minusSeconds(1), refreshToken.getIssuedAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(
				refreshToken.getExpiresAt().minusSeconds(1), refreshToken.getExpiresAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getScope()).isNull();
		assertThat(tokenIntrospectionResponse.getTokenType()).isNull();
		assertThat(tokenIntrospectionResponse.getNotBefore()).isNull();
		assertThat(tokenIntrospectionResponse.getSubject()).isNull();
		assertThat(tokenIntrospectionResponse.getAudience()).isNull();
		assertThat(tokenIntrospectionResponse.getIssuer()).isNull();
		assertThat(tokenIntrospectionResponse.getId()).isNull();
	}

	private static MultiValueMap<String, String> getTokenIntrospectionRequestParameters(AbstractOAuth2Token token,
			OAuth2TokenType tokenType) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames2.TOKEN, token.getTokenValue());
		parameters.set(OAuth2ParameterNames2.TOKEN_TYPE_HINT, tokenType.getValue());
		return parameters;
	}

	private OAuth2TokenIntrospection readTokenIntrospectionResponse(MvcResult mvcResult) throws Exception {
		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
		return this.tokenIntrospectionHttpResponseConverter.read(OAuth2TokenIntrospection.class, httpResponse);
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		OAuth2AuthorizationService authorizationService() {
			return new InMemoryOAuth2AuthorizationService();
		}

		@Bean
		OAuth2AuthorizationConsentService authorizationConsentService() {
			return new InMemoryOAuth2AuthorizationConsentService();
		}

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			// @formatter:off
			RegisteredClient dummyClient = TestRegisteredClients.registeredClient()
					.id("dummy-client")
					.clientId("dummy-client")
					.clientSecret("dummy-secret")
					.build();
			// @formatter:on
			return new InMemoryRegisteredClientRepository(dummyClient);
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return jwkSource;
		}

		@Bean
		ProviderSettings providerSettings() {
			return providerSettings;
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}
}
