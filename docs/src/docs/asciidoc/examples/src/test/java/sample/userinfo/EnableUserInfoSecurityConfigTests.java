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
package sample.userinfo;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sample.AuthorizationCodeGrantFlow;
import sample.test.SpringTestContext;
import sample.test.SpringTestContextExtension;
import sample.userinfo.idtoken.IdTokenCustomizerConfig;
import sample.userinfo.idtoken.OidcUserInfoService;
import sample.userinfo.jwt.JwtTokenCustomizerConfig;
import sample.userinfo.jwt.JwtUserInfoMapperSecurityConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for the guide How-to: Customize the OpenID Connect 1.0 UserInfo response.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class EnableUserInfoSecurityConfigTests {
	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	public void userInfoWhenEnabledThenSuccess() throws Exception {
		this.spring.register(AuthorizationServerConfig.class).autowire();

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("messaging-client");
		assertThat(registeredClient).isNotNull();

		AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
		authorizationCodeGrantFlow.setUsername("user1");
		authorizationCodeGrantFlow.addScope("message.read");
		authorizationCodeGrantFlow.addScope("message.write");

		String state = authorizationCodeGrantFlow.authorize(registeredClient);
		String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
		Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);

		this.mockMvc.perform(get("/userinfo")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON_VALUE)))
				.andExpect(jsonPath("sub").value("user1"));
	}

	@Test
	public void userInfoWhenIdTokenCustomizerThenIdTokenClaimsMappedToResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigWithIdTokenCustomizer.class).autowire();

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("messaging-client");
		assertThat(registeredClient).isNotNull();

		AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
		authorizationCodeGrantFlow.setUsername("user1");
		authorizationCodeGrantFlow.addScope(OidcScopes.ADDRESS);
		authorizationCodeGrantFlow.addScope(OidcScopes.EMAIL);
		authorizationCodeGrantFlow.addScope(OidcScopes.PHONE);
		authorizationCodeGrantFlow.addScope(OidcScopes.PROFILE);

		String state = authorizationCodeGrantFlow.authorize(registeredClient);
		String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
		Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);

		this.mockMvc.perform(get("/userinfo")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON_VALUE)))
				.andExpectAll(
						jsonPath("sub").value("user1"),
						jsonPath("name").value("First Last"),
						jsonPath("given_name").value("First"),
						jsonPath("family_name").value("Last"),
						jsonPath("middle_name").value("Middle"),
						jsonPath("nickname").value("User"),
						jsonPath("preferred_username").value("user1"),
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
	}

	@Test
	public void userInfoWhenUserInfoMapperThenClaimsMappedToResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigWithJwtTokenCustomizer.class).autowire();

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("messaging-client");
		assertThat(registeredClient).isNotNull();

		AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
		authorizationCodeGrantFlow.setUsername("user1");
		authorizationCodeGrantFlow.addScope("message.read");
		authorizationCodeGrantFlow.addScope("message.write");

		String state = authorizationCodeGrantFlow.authorize(registeredClient);
		String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
		Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);

		this.mockMvc.perform(get("/userinfo")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON_VALUE)))
				.andExpectAll(
						jsonPath("sub").value("user1"),
						jsonPath("claim-1").value("value-1"),
						jsonPath("claim-2").value("value-2")
				);
	}

	@EnableWebSecurity
	@EnableAutoConfiguration
	@Import(EnableUserInfoSecurityConfig.class)
	static class AuthorizationServerConfig {

	}

	@EnableWebSecurity
	@Import({EnableUserInfoSecurityConfig.class, IdTokenCustomizerConfig.class})
	static class AuthorizationServerConfigWithIdTokenCustomizer {

		@Bean
		public OidcUserInfoService userInfoService() {
			return new OidcUserInfoService();
		}

	}

	@EnableWebSecurity
	@EnableAutoConfiguration
	@Import({JwtUserInfoMapperSecurityConfig.class, JwtTokenCustomizerConfig.class})
	static class AuthorizationServerConfigWithJwtTokenCustomizer {

	}

}
