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

import javax.servlet.FilterChain;

import org.junit.After;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link AuthorizationServerContextFilter}.
 *
 * @author Joe Grandja
 */
public class AuthorizationServerContextFilterTests {

	@After
	public void cleanup() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthorizationServerSettingsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new AuthorizationServerContextFilter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationServerSettings cannot be null");
	}

	@Test
	public void doFilterWhenIssuerConfiguredThenUsed() throws Exception {
		String issuer = "https://provider.com";
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().issuer(issuer).build();
		AuthorizationServerContextFilter filter = new AuthorizationServerContextFilter(authorizationServerSettings);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setServletPath("/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		doAnswer(invocation -> {
			AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
			assertThat(authorizationServerContext).isNotNull();
			assertThat(authorizationServerContext.getAuthorizationServerSettings()).isSameAs(authorizationServerSettings);
			assertThat(authorizationServerContext.getIssuer()).isEqualTo(issuer);
			return null;
		}).when(filterChain).doFilter(any(), any());

		filter.doFilter(request, response, filterChain);

		assertThat(AuthorizationServerContextHolder.getContext()).isNull();
	}

	@Test
	public void doFilterWhenIssuerNotConfiguredThenResolveFromRequest() throws Exception {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		AuthorizationServerContextFilter filter = new AuthorizationServerContextFilter(authorizationServerSettings);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setServletPath("/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		doAnswer(invocation -> {
			AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
			assertThat(authorizationServerContext).isNotNull();
			assertThat(authorizationServerContext.getAuthorizationServerSettings()).isSameAs(authorizationServerSettings);
			assertThat(authorizationServerContext.getIssuer()).isEqualTo("http://localhost");
			return null;
		}).when(filterChain).doFilter(any(), any());

		filter.doFilter(request, response, filterChain);

		assertThat(AuthorizationServerContextHolder.getContext()).isNull();
	}

}
