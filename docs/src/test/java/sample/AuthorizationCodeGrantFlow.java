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
package sample;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
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

/**
 * Helper class that performs steps of the {@code authorization_code} flow using
 * {@link MockMvc} for testing.
 *
 * @author Steve Riesenberg
 */
public class AuthorizationCodeGrantFlow {
	private static final Pattern HIDDEN_STATE_INPUT_PATTERN = Pattern.compile(".+<input type=\"hidden\" name=\"state\" value=\"([^\"]+)\">.+");
	private static final TypeReference<Map<String, Object>> TOKEN_RESPONSE_TYPE_REFERENCE = new TypeReference<Map<String, Object>>() {
	};

	private final MockMvc mockMvc;

	private String username = "user";

	private Set<String> scopes = new HashSet<>();

	public AuthorizationCodeGrantFlow(MockMvc mockMvc) {
		this.mockMvc = mockMvc;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void addScope(String scope) {
		this.scopes.add(scope);
	}

	/**
	 * Perform the authorization request and obtain a state parameter.
	 *
	 * @param registeredClient The registered client
	 * @return The state parameter for submitting consent for authorization
	 */
	public String authorize(RegisteredClient registeredClient) throws Exception {
		return authorize(registeredClient, null);
	}

	/**
	 * Perform the authorization request and obtain a state parameter.
	 *
	 * @param registeredClient The registered client
	 * @param additionalParameters Additional parameters for the request
	 * @return The state parameter for submitting consent for authorization
	 */
	public String authorize(RegisteredClient registeredClient, MultiValueMap<String, String> additionalParameters) throws Exception {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		parameters.set(OAuth2ParameterNames.STATE, "state");
		if (additionalParameters != null) {
			parameters.addAll(additionalParameters);
		}

		// @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(get("/oauth2/authorize")
				.params(parameters)
				.with(user(this.username).roles("USER")))
				.andExpect(status().isOk())
				.andExpect(header().string("content-type", containsString(MediaType.TEXT_HTML_VALUE)))
				.andReturn();
		// @formatter:on
		String responseHtml = mvcResult.getResponse().getContentAsString();
		Matcher matcher = HIDDEN_STATE_INPUT_PATTERN.matcher(responseHtml);

		return matcher.matches() ? matcher.group(1) : null;
	}

	/**
	 * Submit consent for the authorization request and obtain an authorization code.
	 *
	 * @param registeredClient The registered client
	 * @param state The state parameter from the authorization request
	 * @return An authorization code
	 */
	public String submitConsent(RegisteredClient registeredClient, String state) throws Exception {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.STATE, state);
		for (String scope : scopes) {
			parameters.add(OAuth2ParameterNames.SCOPE, scope);
		}

		// @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(post("/oauth2/authorize")
				.params(parameters)
				.with(user(this.username).roles("USER")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		// @formatter:on
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).isNotNull();
		assertThat(redirectedUrl).matches("\\S+\\?code=.{15,}&state=state");

		String locationHeader = URLDecoder.decode(redirectedUrl, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();

		return uriComponents.getQueryParams().getFirst("code");
	}

	/**
	 * Exchange an authorization code for an access token.
	 *
	 * @param registeredClient The registered client
	 * @param authorizationCode The authorization code obtained from the authorization request
	 * @return The token response
	 */
	public Map<String, Object> getTokenResponse(RegisteredClient registeredClient, String authorizationCode) throws Exception {
		return getTokenResponse(registeredClient, authorizationCode, null);
	}

	/**
	 * Exchange an authorization code for an access token.
	 *
	 * @param registeredClient The registered client
	 * @param authorizationCode The authorization code obtained from the authorization request
	 * @param additionalParameters Additional parameters for the request
	 * @return The token response
	 */
	public Map<String, Object> getTokenResponse(RegisteredClient registeredClient, String authorizationCode, MultiValueMap<String, String> additionalParameters) throws Exception {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.set(OAuth2ParameterNames.CODE, authorizationCode);
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		if (additionalParameters != null) {
			parameters.addAll(additionalParameters);
		}

		boolean publicClient = (registeredClient.getClientSecret() == null);
		HttpHeaders headers = new HttpHeaders();
		if (!publicClient) {
			headers.setBasicAuth(registeredClient.getClientId(),
					registeredClient.getClientSecret().replace("{noop}", ""));
		}

		// @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(post("/oauth2/token")
				.params(parameters)
				.headers(headers))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CONTENT_TYPE, containsString(MediaType.APPLICATION_JSON_VALUE)))
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNotEmpty())
				.andExpect(publicClient
						? jsonPath("$.refresh_token").doesNotExist()
						: jsonPath("$.refresh_token").isNotEmpty()
				)
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andExpect(jsonPath("$.id_token").isNotEmpty())
				.andReturn();
		// @formatter:on

		ObjectMapper objectMapper = new ObjectMapper();
		String responseJson = mvcResult.getResponse().getContentAsString();
		return objectMapper.readValue(responseJson, TOKEN_RESPONSE_TYPE_REFERENCE);
	}

	public static MultiValueMap<String, String> withCodeChallenge() {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(PkceParameterNames.CODE_CHALLENGE, "BqZZ8pTVLsiA3t3tDOys2flJTSH7LoL3Pp5ZqM_YOnE");
		parameters.set(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		return parameters;
	}

	public static MultiValueMap<String, String> withCodeVerifier() {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(PkceParameterNames.CODE_VERIFIER, "yZ6eB-lEB4BBhIzqoDPqXTTATC0Vkgov7qDF8ar2qT4");
		return parameters;
	}
}
