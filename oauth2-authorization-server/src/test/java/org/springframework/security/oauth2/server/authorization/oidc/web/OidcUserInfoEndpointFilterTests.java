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
package org.springframework.security.oauth2.server.authorization.oidc.web;

import java.time.Instant;
import java.util.Collections;

import javax.servlet.FilterChain;

import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OidcUserInfoEndpointFilter}.
 *
 * @author Steve Riesenberg
 */
public class OidcUserInfoEndpointFilterTests {
	private static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcUserInfoEndpointFilter(null))
				.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenUserInfoEndpointUriIsEmptyThenThrowIllegalArgumentException() {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcUserInfoEndpointFilter(authenticationManager, ""))
				.withMessage("userInfoEndpointUri cannot be empty");
	}

	@Test
	public void doFilterWhenNotUserInfoRequestThenNotProcessed() throws Exception {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		OidcUserInfoEndpointFilter userInfoEndpointFilter =
				new OidcUserInfoEndpointFilter(authenticationManager, DEFAULT_OIDC_USER_INFO_ENDPOINT_URI);

		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		userInfoEndpointFilter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(request, response);
	}

	@Test
	public void doFilterWhenUserInfoRequestPutThenNotProcessed() throws Exception {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		OidcUserInfoEndpointFilter userInfoEndpointFilter =
				new OidcUserInfoEndpointFilter(authenticationManager, DEFAULT_OIDC_USER_INFO_ENDPOINT_URI);

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("PUT", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		userInfoEndpointFilter.doFilter(request, response, filterChain);

		verifyNoInteractions(authenticationManager);
		verify(filterChain).doFilter(request, response);
	}

	@Test
	public void doFilterWhenUserInfoRequestGetThenSuccess() throws Exception {
		JwtAuthenticationToken principal = createJwtAuthenticationToken();
		SecurityContextHolder.getContext().setAuthentication(principal);

		OidcUserInfoAuthenticationToken authenticationResult = new OidcUserInfoAuthenticationToken(principal, createUserInfo());
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		when(authenticationManager.authenticate(any())).thenReturn(authenticationResult);
		OidcUserInfoEndpointFilter userInfoEndpointFilter = new OidcUserInfoEndpointFilter(authenticationManager);

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		userInfoEndpointFilter.doFilter(request, response, filterChain);

		verify(authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertUserInfoResponse(response.getContentAsString());
	}

	@Test
	public void doFilterWhenUserInfoRequestPostThenSuccess() throws Exception {
		JwtAuthenticationToken principal = createJwtAuthenticationToken();
		SecurityContextHolder.getContext().setAuthentication(principal);

		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal, createUserInfo());
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		when(authenticationManager.authenticate(any())).thenReturn(authentication);
		OidcUserInfoEndpointFilter userInfoEndpointFilter = new OidcUserInfoEndpointFilter(authenticationManager);

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		userInfoEndpointFilter.doFilter(request, response, filterChain);

		verify(authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertUserInfoResponse(response.getContentAsString());
	}

	@Test
	public void doFilterWhenAuthenticationNullThenInvalidRequestError() throws Exception {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		when(authenticationManager.authenticate(any(Authentication.class)))
				.thenReturn(new UsernamePasswordAuthenticationToken("user", "password"));
		OidcUserInfoEndpointFilter userInfoEndpointFilter = new OidcUserInfoEndpointFilter(authenticationManager);

		String requestUri = DEFAULT_OIDC_USER_INFO_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		userInfoEndpointFilter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		assertThat(error.getDescription()).isEqualTo("OpenID Connect 1.0 UserInfo Error: principal cannot be null");
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private JwtAuthenticationToken createJwtAuthenticationToken() {
		Instant now = Instant.now();
		// @formatter:off
		Jwt jwt = Jwt.withTokenValue("token")
				.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
				.issuedAt(now)
				.expiresAt(now.plusSeconds(300))
				.claim(StandardClaimNames.SUB, "user")
				.build();
		// @formatter:on
		return new JwtAuthenticationToken(jwt, Collections.emptyList());
	}

	private static OidcUserInfo createUserInfo() {
		return OidcUserInfo.builder()
				.subject("user1")
				.name("First Last")
				.givenName("First")
				.familyName("Last")
				.middleName("Middle")
				.nickname("User")
				.preferredUsername("user")
				.profile("https://example.com/user1")
				.picture("https://example.com/user1.jpg")
				.website("https://example.com")
				.email("user1@example.com")
				.emailVerified(true)
				.gender("female")
				.birthdate("1970-01-01")
				.zoneinfo("Europe/Paris")
				.locale("en-US")
				.phoneNumber("+1 (604) 555-1234;ext=5678")
				.phoneNumberVerified("false")
				.address("Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance")
				.updatedAt("1970-01-01T00:00:00Z")
				.build();
	}

	private static void assertUserInfoResponse(String userInfoResponse) {
		assertThat(userInfoResponse).contains("\"sub\":\"user1\"");
		assertThat(userInfoResponse).contains("\"name\":\"First Last\"");
		assertThat(userInfoResponse).contains("\"given_name\":\"First\"");
		assertThat(userInfoResponse).contains("\"family_name\":\"Last\"");
		assertThat(userInfoResponse).contains("\"middle_name\":\"Middle\"");
		assertThat(userInfoResponse).contains("\"nickname\":\"User\"");
		assertThat(userInfoResponse).contains("\"preferred_username\":\"user\"");
		assertThat(userInfoResponse).contains("\"profile\":\"https://example.com/user1\"");
		assertThat(userInfoResponse).contains("\"picture\":\"https://example.com/user1.jpg\"");
		assertThat(userInfoResponse).contains("\"website\":\"https://example.com\"");
		assertThat(userInfoResponse).contains("\"email\":\"user1@example.com\"");
		assertThat(userInfoResponse).contains("\"email_verified\":true");
		assertThat(userInfoResponse).contains("\"gender\":\"female\"");
		assertThat(userInfoResponse).contains("\"birthdate\":\"1970-01-01\"");
		assertThat(userInfoResponse).contains("\"zoneinfo\":\"Europe/Paris\"");
		assertThat(userInfoResponse).contains("\"locale\":\"en-US\"");
		assertThat(userInfoResponse).contains("\"phone_number\":\"+1 (604) 555-1234;ext=5678\"");
		assertThat(userInfoResponse).contains("\"phone_number_verified\":\"false\"");
		assertThat(userInfoResponse).contains("\"address\":\"Champ de Mars\\n5 Av. Anatole France\\n75007 Paris\\nFrance\"");
		assertThat(userInfoResponse).contains("\"updated_at\":\"1970-01-01T00:00:00Z\"");
	}
}
