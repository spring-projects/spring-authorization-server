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
package sample.pkce;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sample.AuthorizationCodeGrantFlow;
import sample.test.SpringTestContext;
import sample.test.SpringTestContextExtension;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static sample.AuthorizationCodeGrantFlow.withCodeChallenge;
import static sample.AuthorizationCodeGrantFlow.withCodeVerifier;

/**
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class PublicClientTests {
	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	public void oidcLoginWhenPublicClientThenSuccess() throws Exception {
		this.spring.register(AuthorizationServerConfig.class).autowire();

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("public-client");
		assertThat(registeredClient).isNotNull();

		AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
		authorizationCodeGrantFlow.setUsername("user");
		authorizationCodeGrantFlow.addScope(OidcScopes.OPENID);
		authorizationCodeGrantFlow.addScope(OidcScopes.PROFILE);

		String state = authorizationCodeGrantFlow.authorize(registeredClient, withCodeChallenge());
		assertThat(state).isNotNull();

		String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
		assertThat(authorizationCode).isNotNull();

		Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient,
				authorizationCode, withCodeVerifier());
		assertThat(tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull();
		// Note: Refresh tokens are not issued to public clients
		assertThat(tokenResponse.get(OAuth2ParameterNames.REFRESH_TOKEN)).isNull();
		assertThat(tokenResponse.get(OidcParameterNames.ID_TOKEN)).isNotNull();
	}

	@EnableWebSecurity
	@EnableAutoConfiguration
	@ComponentScan
	static class AuthorizationServerConfig {

	}

}
