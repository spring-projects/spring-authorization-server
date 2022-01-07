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
package sample.jpa;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sample.jose.TestJwks;
import sample.test.SpringTestContext;
import sample.test.SpringTestContextExtension;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static sample.util.RegisteredClients.messagingClient;

/**
 * Tests for the guide How-to: Implement core services with JPA.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class JpaTests {

	private static final Pattern HIDDEN_STATE_INPUT_PATTERN = Pattern.compile(".+<input type=\"hidden\" name=\"state\" value=\"([^\"]+)\">.+");
	private static final TypeReference<Map<String, Object>> TOKEN_RESPONSE_TYPE_REFERENCE = new TypeReference<Map<String, Object>>() {
	};

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@Autowired
	private OAuth2AuthorizationConsentService authorizationConsentService;

	@Test
	public void oidcLoginWhenJpaCoreServicesAutowiredThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfig.class).autowire();
		assertThat(this.registeredClientRepository).isInstanceOf(JpaRegisteredClientRepository.class);
		assertThat(this.authorizationService).isInstanceOf(JpaOAuth2AuthorizationService.class);
		assertThat(this.authorizationConsentService).isInstanceOf(JpaOAuth2AuthorizationConsentService.class);

		RegisteredClient registeredClient = messagingClient();
		this.registeredClientRepository.save(registeredClient);

		String state = performAuthorizationCodeRequest(registeredClient);
		assertThatAuthorization(state, OAuth2ParameterNames.STATE).isNotNull();
		assertThatAuthorization(state, null).isNotNull();

		String authorizationCode = performAuthorizationConsentRequest(registeredClient, state);
		assertThatAuthorization(authorizationCode, OAuth2ParameterNames.CODE).isNotNull();
		assertThatAuthorization(authorizationCode, null).isNotNull();

		Map<String, Object> tokenResponse = performTokenRequest(registeredClient, authorizationCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);
		assertThatAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN).isNotNull();
		assertThatAuthorization(accessToken, null).isNotNull();

		String refreshToken = (String) tokenResponse.get(OAuth2ParameterNames.REFRESH_TOKEN);
		assertThatAuthorization(refreshToken, OAuth2ParameterNames.REFRESH_TOKEN).isNotNull();
		assertThatAuthorization(refreshToken, null).isNotNull();

		String idToken = (String) tokenResponse.get(OidcParameterNames.ID_TOKEN);
		assertThatAuthorization(idToken, OidcParameterNames.ID_TOKEN).isNull(); // id_token is not searchable

		OAuth2Authorization authorization = findAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN);
		assertThat(authorization.getToken(idToken)).isNotNull();

		String scopes = (String) tokenResponse.get(OAuth2ParameterNames.SCOPE);
		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService.findById(
				registeredClient.getId(), "user");
		assertThat(authorizationConsent).isNotNull();
		assertThat(authorizationConsent.getScopes()).containsExactlyInAnyOrder(
				StringUtils.delimitedListToStringArray(scopes, " "));
	}

	private ObjectAssert<OAuth2Authorization> assertThatAuthorization(String token, String tokenType) {
		return assertThat(findAuthorization(token, tokenType));
	}

	private OAuth2Authorization findAuthorization(String token, String tokenType) {
		return this.authorizationService.findByToken(token, tokenType == null ? null : new OAuth2TokenType(tokenType));
	}

	private String performAuthorizationCodeRequest(RegisteredClient registeredClient) throws Exception {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		parameters.set(OAuth2ParameterNames.STATE, "state");

		MvcResult mvcResult = this.mockMvc.perform(get("/oauth2/authorize")
				.params(parameters)
				.with(user("user").roles("USER")))
				.andExpect(status().isOk())
				.andExpect(header().string("content-type", containsString(MediaType.TEXT_HTML_VALUE)))
				.andReturn();
		String responseHtml = mvcResult.getResponse().getContentAsString();
		Matcher matcher = HIDDEN_STATE_INPUT_PATTERN.matcher(responseHtml);

		return matcher.matches() ? matcher.group(1) : null;
	}

	private String performAuthorizationConsentRequest(RegisteredClient registeredClient, String state) throws Exception {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.STATE, state);
		parameters.add(OAuth2ParameterNames.SCOPE, "message.read");
		parameters.add(OAuth2ParameterNames.SCOPE, "message.write");

		MvcResult mvcResult = this.mockMvc.perform(post("/oauth2/authorize")
				.params(parameters)
				.with(user("user").roles("USER")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).isNotNull();
		assertThat(redirectedUrl).matches("http://127.0.0.1:8080/authorized\\?code=.{15,}&state=state");

		String locationHeader = URLDecoder.decode(redirectedUrl, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();

		return uriComponents.getQueryParams().getFirst("code");
	}

	private Map<String, Object> performTokenRequest(RegisteredClient registeredClient, String authorizationCode) throws Exception {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.set(OAuth2ParameterNames.CODE, authorizationCode);
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());

		HttpHeaders basicAuth = new HttpHeaders();
		basicAuth.setBasicAuth(registeredClient.getClientId(), "secret");

		MvcResult mvcResult = this.mockMvc.perform(post("/oauth2/token")
				.params(parameters)
				.headers(basicAuth))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CONTENT_TYPE, containsString(MediaType.APPLICATION_JSON_VALUE)))
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").isNotEmpty())
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andExpect(jsonPath("$.id_token").isNotEmpty())
				.andReturn();

		ObjectMapper objectMapper = new ObjectMapper();
		String responseJson = mvcResult.getResponse().getContentAsString();
		return objectMapper.readValue(responseJson, TOKEN_RESPONSE_TYPE_REFERENCE);
	}

	@EnableWebSecurity
	@EnableAutoConfiguration
	@ComponentScan
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfig {

		@Bean
		public JWKSource<SecurityContext> jwkSource() {
			JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
			return new ImmutableJWKSet<>(jwkSet);
		}

		@Bean
		public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

	}

}
