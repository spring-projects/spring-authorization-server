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
package sample.dcr;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


/**
 * Tests for Dynamic Client Registration how-to guide
 *
 * @author Dmitriy Dubson
 */
@SpringBootTest(
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		classes = {DynamicClientRegistrationTests.AuthorizationServerConfig.class}
)
@AutoConfigureMockMvc
public class DynamicClientRegistrationTests {

	@Autowired
	private MockMvc mvc;

	@LocalServerPort
	private String port;

	@Test
	public void dynamicallyRegisterAClient() throws Exception {
		String tokenRequestBody = "scope=client.create&grant_type=client_credentials" ;
		MockHttpServletResponse tokenResponse = this.mvc.perform(post("/oauth2/token")
						.with(httpBasic("dcr-client", "secret"))
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.content(tokenRequestBody))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andReturn()
				.getResponse();

		String initialAccessToken = JsonPath.parse(tokenResponse.getContentAsString()).read("$.access_token");

		WebClient webClient = WebClient.builder().baseUrl("http://127.0.0.1:%s".formatted(port)).build();
		DcrClient dcrClient = new DcrClient(webClient);

		dcrClient.exampleRegistration(initialAccessToken);
	}

	@EnableAutoConfiguration
	@EnableWebSecurity
	@Import({DcrConfiguration.class, RegisteredClientConfiguration.class})
	static class AuthorizationServerConfig {
	}
}
