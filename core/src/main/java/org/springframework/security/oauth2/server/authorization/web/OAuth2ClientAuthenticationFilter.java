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

import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 */
public class OAuth2ClientAuthenticationFilter extends OncePerRequestFilter {

	public static final String DEFAULT_FILTER_PROCESSES_URL = "/oauth2/token";
	private final AuthenticationManager authenticationManager;
	private final RequestMatcher requestMatcher;
	private final OAuth2ErrorHttpMessageConverter errorMessageConverter = new OAuth2ErrorHttpMessageConverter();
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	private AuthenticationFailureHandler authenticationFailureHandler;
	private AuthenticationConverter authenticationConverter = new DefaultOAuth2ClientAuthenticationConverter();

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager}.
	 *
	 * @param authenticationManager
	 * 		the bean to submit authentication requests to
	 */
	public OAuth2ClientAuthenticationFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_FILTER_PROCESSES_URL);
	}

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager}.
	 *
	 * <p>
	 * Configures default {@link RequestMatcher} verifying the provided endpoint.
	 *
	 * @param authenticationManager
	 * 		the bean to submit authentication requests to
	 * @param filterProcessesUrl
	 * 		the filterProcessesUrl to match request URI against
	 */
	public OAuth2ClientAuthenticationFilter(AuthenticationManager authenticationManager, String filterProcessesUrl) {
		this(authenticationManager, new AntPathRequestMatcher(filterProcessesUrl, "POST"));
	}

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager} and custom {@code RequestMatcher}.
	 *
	 * @param authenticationManager
	 * 		the bean to submit authentication requests to
	 * @param requestMatcher
	 * 		the {@code RequestMatcher} to match {@code HttpServletRequest} against
	 */
	public OAuth2ClientAuthenticationFilter(AuthenticationManager authenticationManager,
			RequestMatcher requestMatcher) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.authenticationManager = authenticationManager;
		this.requestMatcher = requestMatcher;
		this.authenticationSuccessHandler = this::defaultAuthenticationSuccessHandler;
		this.authenticationFailureHandler = this::defaultAuthenticationFailureHandler;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.requestMatcher.matches(request)) {
			Authentication authentication = this.authenticationConverter.convert(request);
			if (authentication == null) {
				filterChain.doFilter(request, response);
				return;
			}
			try {
				final Authentication result = this.authenticationManager.authenticate(authentication);
				this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, result);
			} catch (OAuth2AuthenticationException failed) {
				this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed);
				return;
			}
		}
		filterChain.doFilter(request, response);
	}

	/**
	 * Used to define custom behaviour on a successful authentication.
	 *
	 * @param authenticationSuccessHandler
	 * 		the handler to be used
	 */
	public final void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Used to define custom behaviour on a failed authentication.
	 *
	 * @param authenticationFailureHandler
	 * 		the handler to be used
	 */
	public final void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Used to define custom {@link AuthenticationConverter}.
	 *
	 * @param authenticationConverter
	 * 		the converter to be used
	 */
	public final void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	private void defaultAuthenticationSuccessHandler(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {

		SecurityContextHolder.getContext()
				.setAuthentication(authentication);
	}

	private void defaultAuthenticationFailureHandler(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException {

		SecurityContextHolder.clearContext();
		this.errorMessageConverter.write(((OAuth2AuthenticationException) failed).getError(),
				MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
	}
}
