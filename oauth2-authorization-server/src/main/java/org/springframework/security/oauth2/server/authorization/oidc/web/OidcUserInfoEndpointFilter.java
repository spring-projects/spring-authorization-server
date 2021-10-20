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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that processes OpenID Connect 1.0 UserInfo Requests.
 *
 * @author Ido Salomon
 * @author Steve Riesenberg
 * @since 0.2.1
 * @see OidcUserInfo
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">5.3. UserInfo Endpoint</a>
 */
public final class OidcUserInfoEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for OpenID Connect 1.0 UserInfo Requests.
	 */
	private static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher userInfoEndpointMatcher;

	private final HttpMessageConverter<OidcUserInfo> userInfoHttpMessageConverter =
			new OidcUserInfoHttpMessageConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();

	/**
	 * Constructs an {@code OidcUserInfoEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public OidcUserInfoEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_OIDC_USER_INFO_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OidcUserInfoEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param userInfoEndpointUri the endpoint {@code URI} for OpenID Connect 1.0 UserInfo Requests
	 */
	public OidcUserInfoEndpointFilter(AuthenticationManager authenticationManager, String userInfoEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(userInfoEndpointUri, "userInfoEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.userInfoEndpointMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(userInfoEndpointUri, HttpMethod.GET.name()),
				new AntPathRequestMatcher(userInfoEndpointUri, HttpMethod.POST.name()));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.userInfoEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication principal = SecurityContextHolder.getContext().getAuthentication();

			OidcUserInfoAuthenticationToken userInfoAuthentication = new OidcUserInfoAuthenticationToken(principal);

			OidcUserInfoAuthenticationToken userInfoAuthenticationResult =
					(OidcUserInfoAuthenticationToken) this.authenticationManager.authenticate(userInfoAuthentication);

			sendUserInfoResponse(response, userInfoAuthenticationResult.getUserInfo());

		} catch (OAuth2AuthenticationException ex) {
			sendErrorResponse(response, ex.getError());
		} catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(
					OAuth2ErrorCodes.INVALID_REQUEST,
					"OpenID Connect 1.0 UserInfo Error: " + ex.getMessage(),
					"https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError");
			sendErrorResponse(response, error);
		} finally {
			SecurityContextHolder.clearContext();
		}
	}

	private void sendUserInfoResponse(HttpServletResponse response, OidcUserInfo userInfo) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.userInfoHttpMessageConverter.write(userInfo, MediaType.APPLICATION_JSON, httpResponse);
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_TOKEN)) {
			httpStatus = HttpStatus.UNAUTHORIZED;
		} else if (error.getErrorCode().equals(OAuth2ErrorCodes.INSUFFICIENT_SCOPE)) {
			httpStatus = HttpStatus.FORBIDDEN;
		}
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(httpStatus);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}
}
