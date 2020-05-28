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
package org.springframework.security.oauth2.server.authorization.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2TokenRevocationEndpointFilter}.
 *
 * @author Vivek Babu
 */
public class OAuth2TokenRevocationEndpointFilterTests {
	private static final String TOKEN = "token";
	private static final String TOKEN_TYPE_HINT = "token_type_hint";
	private AuthenticationManager authenticationManager;
	private OAuth2TokenRevocationEndpointFilter filter;
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();

	@Before
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2TokenRevocationEndpointFilter(this.authenticationManager);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationEndpointFilter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenTokenEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenRevocationEndpointFilter(this.authenticationManager, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("revocationEndpointUri cannot be empty");
	}

	@Test
	public void doFilterWhenNotRevocationRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenRevocationRequestGetThenNotProcessed() throws Exception {
		String requestUri = OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenRevocationRequestMissingTokenThenInvalidRequestError() throws Exception {
		doFilterWhenRevocationRequestInvalidParameterThenError(
				TOKEN, OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.removeParameter(TOKEN));
	}

	@Test
	public void doFilterWhenRevocationRequestMultipleTokenThenInvalidRequestError() throws Exception {
		doFilterWhenRevocationRequestInvalidParameterThenError(
				TOKEN, OAuth2ErrorCodes.INVALID_REQUEST,
				request -> {
					request.addParameter(TOKEN, "token-1");
					request.addParameter(TOKEN, "token-2");
				});
	}

	@Test
	public void doFilterWhenTokenRequestValidThenAccessTokenResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);

		Authentication tokenRevocationAuthenticationSuccess = mock(Authentication.class);

		when(this.authenticationManager.authenticate(any())).thenReturn(tokenRevocationAuthenticationSuccess);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest request = createRevocationRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		ArgumentCaptor<OAuth2TokenRevocationAuthenticationToken> tokenRevocationAuthenticationCaptor =
				ArgumentCaptor.forClass(OAuth2TokenRevocationAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(tokenRevocationAuthenticationCaptor.capture());

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
	}

	private void doFilterWhenRevocationRequestInvalidParameterThenError(String parameterName, String errorCode,
			Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		MockHttpServletRequest request = createRevocationRequest();
		requestConsumer.accept(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
		assertThat(error.getDescription()).isEqualTo("Token Revocation Request Parameter: " + parameterName);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private static MockHttpServletRequest createRevocationRequest() {

		String requestUri = OAuth2TokenRevocationEndpointFilter.DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);

		request.addParameter(TOKEN, "token");
		request.addParameter(TOKEN_TYPE_HINT, "access_token");

		return request;
	}
}
