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
package org.springframework.security.oauth2.server.authorization.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2ClientAuthenticationFilter}.
 *
 * @author Patryk Kostrzewa
 * @author Joe Grandja
 */
public class OAuth2ClientAuthenticationFilterTests {
	private String filterProcessesUrl = "/oauth2/token";
	private AuthenticationManager authenticationManager;
	private RequestMatcher requestMatcher;
	private AuthenticationConverter authenticationConverter;
	private OAuth2ClientAuthenticationFilter filter;
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.requestMatcher = new AntPathRequestMatcher(this.filterProcessesUrl, HttpMethod.POST.name());
		this.filter = new OAuth2ClientAuthenticationFilter(this.authenticationManager, this.requestMatcher);
		this.authenticationConverter = mock(AuthenticationConverter.class);
		this.filter.setAuthenticationConverter(this.authenticationConverter);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientAuthenticationFilter(null, this.requestMatcher))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenRequestMatcherNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientAuthenticationFilter(this.authenticationManager, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("requestMatcher cannot be null");
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationConverter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationConverter cannot be null");
	}

	@Test
	public void setAuthenticationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationSuccessHandler(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthenticationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationFailureHandler(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationFailureHandler cannot be null");
	}

	@Test
	public void doFilterWhenRequestDoesNotMatchThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenRequestMatchesAndEmptyCredentialsThenNotProcessed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenRequestMatchesAndInvalidCredentialsThenInvalidRequestError() throws Exception {
		when(this.authenticationConverter.convert(any(HttpServletRequest.class))).thenThrow(
				new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST));

		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void doFilterWhenRequestMatchesAndBadCredentialsThenInvalidClientError() throws Exception {
		when(this.authenticationConverter.convert(any(HttpServletRequest.class))).thenReturn(
				new OAuth2ClientAuthenticationToken("clientId", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "invalid-secret", null));
		when(this.authenticationManager.authenticate(any(Authentication.class))).thenThrow(
				new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT));

		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void doFilterWhenRequestMatchesAndValidCredentialsThenProcessed() throws Exception {
		final String remoteAddress = "remote-address";

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.authenticationConverter.convert(any(HttpServletRequest.class))).thenReturn(
				new OAuth2ClientAuthenticationToken(registeredClient.getClientId(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret(), null));
		when(this.authenticationManager.authenticate(any(Authentication.class))).thenReturn(
				new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret()));

		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		request.setRemoteAddr(remoteAddress);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication).isInstanceOf(OAuth2ClientAuthenticationToken.class);
		assertThat(((OAuth2ClientAuthenticationToken) authentication).getRegisteredClient()).isEqualTo(registeredClient);

		ArgumentCaptor<OAuth2ClientAuthenticationToken> authenticationRequestCaptor =
				ArgumentCaptor.forClass(OAuth2ClientAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(authenticationRequestCaptor.capture());
		assertThat(authenticationRequestCaptor)
				.extracting(ArgumentCaptor::getValue)
				.extracting(OAuth2ClientAuthenticationToken::getDetails)
				.asInstanceOf(type(WebAuthenticationDetails.class))
				.extracting(WebAuthenticationDetails::getRemoteAddress)
				.isEqualTo(remoteAddress);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}
}
