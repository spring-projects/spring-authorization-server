/*
 * Copyright 2020-2024 the original author or authors.
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
package sample.redis;

import java.io.IOException;
import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;
import redis.embedded.RedisServer;
import sample.AuthorizationCodeGrantFlow;
import sample.DeviceAuthorizationGrantFlow;
import sample.redis.service.RedisOAuth2AuthorizationConsentService;
import sample.redis.service.RedisOAuth2AuthorizationService;
import sample.redis.service.RedisRegisteredClientRepository;
import sample.util.RegisteredClients;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for the guide How-to: Implement core services with Redis.
 *
 * @author Joe Grandja
 */
@SpringBootTest(classes = {RedisTests.AuthorizationServerConfig.class})
@AutoConfigureMockMvc
public class RedisTests {
	private static final RegisteredClient TEST_MESSAGING_CLIENT = RegisteredClients.messagingClient();

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@Autowired
	private OAuth2AuthorizationConsentService authorizationConsentService;

	@Test
	public void oidcLoginWhenRedisCoreServicesAutowiredThenUsed() throws Exception {
		assertThat(this.registeredClientRepository).isInstanceOf(RedisRegisteredClientRepository.class);
		assertThat(this.authorizationService).isInstanceOf(RedisOAuth2AuthorizationService.class);
		assertThat(this.authorizationConsentService).isInstanceOf(RedisOAuth2AuthorizationConsentService.class);

		RegisteredClient registeredClient = TEST_MESSAGING_CLIENT;

		AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
		authorizationCodeGrantFlow.setUsername("user");
		authorizationCodeGrantFlow.addScope("message.read");
		authorizationCodeGrantFlow.addScope("message.write");

		String state = authorizationCodeGrantFlow.authorize(registeredClient);
		assertThatAuthorization(state, OAuth2ParameterNames.STATE).isNotNull();
		assertThatAuthorization(state, null).isNotNull();

		String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
		assertThatAuthorization(authorizationCode, OAuth2ParameterNames.CODE).isNotNull();
		assertThatAuthorization(authorizationCode, null).isNotNull();

		Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);
		assertThatAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN).isNotNull();
		assertThatAuthorization(accessToken, null).isNotNull();

		String refreshToken = (String) tokenResponse.get(OAuth2ParameterNames.REFRESH_TOKEN);
		assertThatAuthorization(refreshToken, OAuth2ParameterNames.REFRESH_TOKEN).isNotNull();
		assertThatAuthorization(refreshToken, null).isNotNull();

		String idToken = (String) tokenResponse.get(OidcParameterNames.ID_TOKEN);
		assertThatAuthorization(idToken, OidcParameterNames.ID_TOKEN).isNotNull();
		assertThatAuthorization(idToken, null).isNotNull();

		OAuth2Authorization authorization = findAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN);
		assertThat(authorization.getToken(idToken)).isNotNull();

		String scopes = (String) tokenResponse.get(OAuth2ParameterNames.SCOPE);
		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService.findById(
				registeredClient.getId(), "user");
		assertThat(authorizationConsent).isNotNull();
		assertThat(authorizationConsent.getScopes()).containsExactlyInAnyOrder(
				StringUtils.delimitedListToStringArray(scopes, " "));
	}

	@Test
	public void deviceAuthorizationWhenRedisCoreServicesAutowiredThenUsed() throws Exception {
		assertThat(this.registeredClientRepository).isInstanceOf(RedisRegisteredClientRepository.class);
		assertThat(this.authorizationService).isInstanceOf(RedisOAuth2AuthorizationService.class);
		assertThat(this.authorizationConsentService).isInstanceOf(RedisOAuth2AuthorizationConsentService.class);

		RegisteredClient registeredClient = TEST_MESSAGING_CLIENT;

		DeviceAuthorizationGrantFlow deviceAuthorizationGrantFlow = new DeviceAuthorizationGrantFlow(this.mockMvc);
		deviceAuthorizationGrantFlow.setUsername("user");
		deviceAuthorizationGrantFlow.addScope("message.read");
		deviceAuthorizationGrantFlow.addScope("message.write");

		Map<String, Object> deviceAuthorizationResponse = deviceAuthorizationGrantFlow.authorize(registeredClient);
		String userCode = (String) deviceAuthorizationResponse.get(OAuth2ParameterNames.USER_CODE);
		assertThatAuthorization(userCode, OAuth2ParameterNames.USER_CODE).isNotNull();
		assertThatAuthorization(userCode, null).isNotNull();

		String deviceCode = (String) deviceAuthorizationResponse.get(OAuth2ParameterNames.DEVICE_CODE);
		assertThatAuthorization(deviceCode, OAuth2ParameterNames.DEVICE_CODE).isNotNull();
		assertThatAuthorization(deviceCode, null).isNotNull();

		String state = deviceAuthorizationGrantFlow.submitCode(userCode);
		assertThatAuthorization(state, OAuth2ParameterNames.STATE).isNotNull();
		assertThatAuthorization(state, null).isNotNull();

		deviceAuthorizationGrantFlow.submitConsent(registeredClient, state, userCode);

		Map<String, Object> tokenResponse = deviceAuthorizationGrantFlow.getTokenResponse(registeredClient, deviceCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);
		assertThatAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN).isNotNull();
		assertThatAuthorization(accessToken, null).isNotNull();

		String refreshToken = (String) tokenResponse.get(OAuth2ParameterNames.REFRESH_TOKEN);
		assertThatAuthorization(refreshToken, OAuth2ParameterNames.REFRESH_TOKEN).isNotNull();
		assertThatAuthorization(refreshToken, null).isNotNull();

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

	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = {JpaRepositoriesAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
	@ComponentScan
	static class AuthorizationServerConfig {
	}

	@TestConfiguration
	static class RedisServerConfig {
		private final RedisServer redisServer;

		@Autowired
		private RegisteredClientRepository registeredClientRepository;

		RedisServerConfig() throws IOException {
			this.redisServer = new RedisServer();
		}

		@PostConstruct
		void postConstruct() throws IOException {
			this.redisServer.start();
			this.registeredClientRepository.save(TEST_MESSAGING_CLIENT);
		}

		@PreDestroy
		void preDestroy() throws IOException {
			this.redisServer.stop();
		}

	}

}
