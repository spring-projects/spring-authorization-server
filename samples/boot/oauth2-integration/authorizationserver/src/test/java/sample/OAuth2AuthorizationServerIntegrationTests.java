/*
 * Copyright 2020 the original author or authors.
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
package sample;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;

/**
 * End-to-end Integration Tests for the application using Spring Authorization Server features.
 *
 * @author Gerardo Roza
 */
@SpringBootTest
@AutoConfigureMockMvc
public class OAuth2AuthorizationServerIntegrationTests {

	private static final String CLIENT_ID = "messaging-client";
	private static final String CLIENT_SECRET = "secret";
	private static final String SCOPE = "message.read";
	private static final String REDIRECT_URI = "http://localhost:8080/authorized";
	private static final String DEFAULT_AUTHORIZE_ENDPOINT = "/oauth2/authorize";
	private static final String DEFAULT_TOKEN_ENDPOINT = "/oauth2/token";
	private static final String DEFAULT_TOKEN_INTROSPECTION_ENDPOINT = "/oauth2/introspect";

	@Test
	@WithMockUser
	void givenValidToken_whenIntrospectToken_thenOkResponseWithPopulatedFields(@Autowired MockMvc mvc)
			throws Exception {
		MvcResult result = obtainAccessTokenResponse(mvc);

		String accessToken = JsonPath.read(result.getResponse().getContentAsString(), "$.access_token");
		String refreshToken = JsonPath.read(result.getResponse().getContentAsString(), "$.refresh_token");

		String urlPatternRegex = "^(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";

		// @formatter:off
		mvc.perform(post(DEFAULT_TOKEN_INTROSPECTION_ENDPOINT)
				.with(anonymous())
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET))
				.param("token", accessToken)
				.param("token_type_hint", "access_token"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.active", is(true)))
			.andExpect(jsonPath("$.scope", is("message.read")))
			.andExpect(jsonPath("$.sub", is("user")))
			.andExpect(jsonPath("$.aud", contains("messaging-client")))
			.andExpect(jsonPath("$.iss", matchesPattern(urlPatternRegex)))
			.andExpect(jsonPath("$.token_type", is("Bearer")))
			.andExpect(jsonPath("$.client_id").isString())
			.andExpect(jsonPath("$.iat", lessThan(Instant.now().getEpochSecond()), Long.class))
			.andExpect(jsonPath("$.nbf", lessThan(Instant.now().getEpochSecond()), Long.class))
			.andExpect(jsonPath("$.exp", greaterThan(Instant.now().getEpochSecond()), Long.class));
		// @formatter:on

		// @formatter:off
		mvc.perform(post(DEFAULT_TOKEN_INTROSPECTION_ENDPOINT)
				.with(anonymous())
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET))
				.param("token", refreshToken)
				.param("token_type_hint", "access_token"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.active", is(true)))
			.andExpect(jsonPath("$.client_id").isString())
			.andExpect(jsonPath("$.iat", lessThan(Instant.now().getEpochSecond()), Long.class))
			.andExpect(jsonPath("$.exp", greaterThan(Instant.now().getEpochSecond()), Long.class));
		// @formatter:on
	}

	@Test
	@WithMockUser
	void givenNonExistingToken_whenIntrospectToken_thenOkResponseWithNonActiveToken(@Autowired MockMvc mvc)
			throws Exception {
		// @formatter:off
		mvc.perform(post(DEFAULT_TOKEN_INTROSPECTION_ENDPOINT).with(httpBasic(CLIENT_ID, CLIENT_SECRET)).param("token",
				"nonExisting"))
		.andExpect(status().isOk())
		.andExpect(jsonPath("$.active", is(false)))
		.andExpect(jsonPath("$.scope").doesNotExist())
		.andExpect(jsonPath("$.sub").doesNotExist())
		.andExpect(jsonPath("$.aud").doesNotExist())
		.andExpect(jsonPath("$.iss").doesNotExist())
		.andExpect(jsonPath("$.token_type").doesNotExist())
		.andExpect(jsonPath("$.client_id").doesNotExist())
		.andExpect(jsonPath("$.iat").doesNotExist())
		.andExpect(jsonPath("$.nbf").doesNotExist())
		.andExpect(jsonPath("$.exp").doesNotExist());
		// @formatter:on
	}

	private MvcResult obtainAccessTokenResponse(MockMvc mvc) throws Exception {
		// authorize/consent page
		MvcResult result = mvc
				.perform(get(DEFAULT_AUTHORIZE_ENDPOINT)
						.queryParam("client_id", CLIENT_ID).queryParam("response_type", "code")
						.queryParam("scope", SCOPE).queryParam("redirect_uri", REDIRECT_URI).queryParam("state", "123"))
				.andExpect(status().isOk())
				.andExpect(
						content().string(allOf(containsString("Consent required"), containsString("messaging-client"),
								containsString("message.read"), not(containsString("message.write")))))
				.andReturn();

		// consent response
		String state = result.getResponse().getContentAsString().split("state\" value=\"")[1].split("\"")[0];
		result = mvc
				.perform(post(DEFAULT_AUTHORIZE_ENDPOINT).param("client_id", CLIENT_ID).param("scope", SCOPE)
						.param("consent_action", "approve").param("state", state))
				.andExpect(status().isFound()).andReturn();

		UriComponents redirectedUri = UriComponentsBuilder
				.fromUriString(result.getResponse().getHeader(HttpHeaders.LOCATION)).build();

		// redirect to client endpoint
		assertThat(redirectedUri.toUri()).hasParameter("state", "123").hasParameter("code");
		String authCode = redirectedUri.getQueryParams().getFirst("code");

		// token request
		return mvc.perform(post(DEFAULT_TOKEN_ENDPOINT).with(httpBasic(CLIENT_ID, CLIENT_SECRET))
				.param("grant_type", "authorization_code").param("code", authCode).param("redirect_uri", REDIRECT_URI))
				.andExpect(status().isOk()).andExpect(jsonPath("$.access_token", notNullValue())).andReturn();

	}

}
