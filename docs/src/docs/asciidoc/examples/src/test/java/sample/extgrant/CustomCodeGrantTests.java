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
package sample.extgrant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import sample.test.SpringTestContext;
import sample.test.SpringTestContextExtension;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringTestContextExtension.class)
public class CustomCodeGrantTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenTokenRequestValidThenTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfig.class).autowire();

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("messaging-client");

		HttpHeaders headers = new HttpHeaders();
		headers.setBasicAuth(registeredClient.getClientId(),
				registeredClient.getClientSecret().replace("{noop}", ""));

		// @formatter:off
		this.mvc.perform(post("/oauth2/token")
				.param(OAuth2ParameterNames.GRANT_TYPE, "urn:ietf:params:oauth:grant-type:custom_code")
				.param(OAuth2ParameterNames.CODE, "7QR49T1W3")
				.headers(headers))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty());
		// @formatter:on
	}

	@EnableWebSecurity
	@EnableAutoConfiguration
	@ComponentScan
	static class AuthorizationServerConfig {
	}

}
