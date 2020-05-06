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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.util.Assert;

import static java.net.URI.create;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getEncoder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class ClientCredentialsAuthenticationFilterTests {
	private static final String CLIENT_ID = "myclientid";
	private static final String CLIENT_SECRET = "myclientsecret";
	private final AuthenticationManager authenticationManager = authentication -> {
		Assert.isInstanceOf(OAuth2ClientAuthenticationToken.class, authentication);
		OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) authentication;
		if (CLIENT_ID.equals(token.getPrincipal()) && CLIENT_SECRET.equals(token.getCredentials())) {
			authentication.setAuthenticated(true);
			return authentication;
		}
		throw new BadCredentialsException("Bad credentials");
	};
	private final ClientCredentialsAuthenticationFilter filter = new ClientCredentialsAuthenticationFilter(this.authenticationManager);

	@BeforeEach
	public void setup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterWhenUrlDoesNotMatchThenDontAuthenticate() throws Exception {
		MockHttpServletRequest request = post(create("/someotherendpoint")).buildRequest(new MockServletContext());
		request.addHeader("Authorization", basicAuthHeader(CLIENT_ID, CLIENT_SECRET));

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void doFilterWhenRequestMatchesThenAuthenticate() throws Exception {
		MockHttpServletRequest request = post(create("/oauth2/token")).buildRequest(new MockServletContext());
		request.addHeader("Authorization", basicAuthHeader(CLIENT_ID, CLIENT_SECRET));

		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

		assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isTrue();
	}

	@Test
	public void doFilterWhenBasicAuthenticationHeaderIsMissingThenThrowBadCredentialsException() {
		MockHttpServletRequest request = post(create("/oauth2/token")).buildRequest(new MockServletContext());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() ->
				filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain()));
	}

	@Test
	public void doFilterWhenBasicAuthenticationHeaderHasInvalidSyntaxThenThrowBadCredentialsException() {
		MockHttpServletRequest request = post(create("/oauth2/token")).buildRequest(new MockServletContext());
		request.addHeader("Authorization", "Basic invalid");

		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() ->
				filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain()));
	}

	@Test
	public void doFilterWhenBasicAuthenticationProvidesIncorrectSecretThenThrowBadCredentialsException() {
		MockHttpServletRequest request = post(create("/oauth2/token")).buildRequest(new MockServletContext());
		request.addHeader("Authorization", basicAuthHeader(CLIENT_ID, "incorrectsecret"));

		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() ->
				filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain()));
	}

	@Test
	public void doFilterWhenBasicAuthenticationProvidesIncorrectClientIdThenThrowBadCredentialsException() {
		MockHttpServletRequest request = post(create("/oauth2/token")).buildRequest(new MockServletContext());
		request.addHeader("Authorization", basicAuthHeader("anotherclientid", CLIENT_SECRET));

		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() ->
				filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain()));
	}

	private static String basicAuthHeader(String clientId, String clientSecret) {
		return "Basic " + getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(UTF_8));
	}
}
