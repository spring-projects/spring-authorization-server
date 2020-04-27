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

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2ClientAuthenticationFilter}.
 *
 * @author Patryk Kostrzewa
 */
public class OAuth2ClientAuthenticationFilterTests {

	private OAuth2ClientAuthenticationFilter filter;
	private AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
	private RequestMatcher requestMatcher = mock(RequestMatcher.class);
	private FilterChain filterChain = mock(FilterChain.class);
	private String filterProcessesUrl;

	@Before
	public void setUp() {
		this.filterProcessesUrl = "/oauth2/token";
		this.filter = new OAuth2ClientAuthenticationFilter(authenticationManager, requestMatcher);
	}

	@Test
	public void constructorManagerAndMatcherWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			new OAuth2ClientAuthenticationFilter(null, (RequestMatcher) null);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorManagerAndFilterUrlWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			new OAuth2ClientAuthenticationFilter(null, (String) null);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void doFilterWhenNotTokenRequestThenNextFilter() throws Exception {
		this.filterProcessesUrl = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verify(this.filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthenticationRequestGetThenNotProcessed() throws Exception {
		String requestUri = OAuth2ClientAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URL;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verify(this.filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthenticationIsNullThenNotProcessed() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.filterProcessesUrl);
		request.setServletPath(this.filterProcessesUrl);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verify(this.filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}
}
