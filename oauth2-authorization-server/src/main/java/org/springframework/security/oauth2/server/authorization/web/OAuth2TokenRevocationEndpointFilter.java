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

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A {@code Filter} for the OAuth 2.0 Token Revocation endpoint.
 *
 * @author Vivek Babu
 * @author Joe Grandja
 * @see OAuth2TokenRevocationAuthenticationProvider
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7009#section-2">Section 2 Token Revocation</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7009#section-2.1">Section 2.1 Revocation Request</a>
 * @since 0.0.3
 */
public class OAuth2TokenRevocationEndpointFilter extends OncePerRequestFilter {
	static final String TOKEN_PARAM_NAME = "token";
	static final String TOKEN_TYPE_HINT_PARAM_NAME = "token_type_hint";

	/**
	 * The default endpoint {@code URI} for token revocation requests.
	 */
	public static final String DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI = "/oauth2/revoke";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher tokenRevocationEndpointMatcher;
	private final Converter<HttpServletRequest, Authentication> tokenRevocationAuthenticationConverter =
			new DefaultTokenRevocationAuthenticationConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();

	/**
	 * Constructs an {@code OAuth2TokenRevocationEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2TokenRevocationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenRevocationEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param tokenRevocationEndpointUri the endpoint {@code URI} for token revocation requests
	 */
	public OAuth2TokenRevocationEndpointFilter(AuthenticationManager authenticationManager,
			String tokenRevocationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(tokenRevocationEndpointUri, "tokenRevocationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.tokenRevocationEndpointMatcher = new AntPathRequestMatcher(
				tokenRevocationEndpointUri, HttpMethod.POST.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenRevocationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			this.authenticationManager.authenticate(
					this.tokenRevocationAuthenticationConverter.convert(request));
			response.setStatus(HttpStatus.OK.value());
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			sendErrorResponse(response, ex.getError());
		}
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Token Revocation Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc7009#section-2.1");
		throw new OAuth2AuthenticationException(error);
	}

	private static class DefaultTokenRevocationAuthenticationConverter
			implements Converter<HttpServletRequest, Authentication> {

		@Override
		public Authentication convert(HttpServletRequest request) {
			Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

			MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

			// token (REQUIRED)
			String token = parameters.getFirst(TOKEN_PARAM_NAME);
			if (!StringUtils.hasText(token) ||
					parameters.get(TOKEN_PARAM_NAME).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, TOKEN_PARAM_NAME);
			}

			// token_type_hint (OPTIONAL)
			String tokenTypeHint = parameters.getFirst(TOKEN_TYPE_HINT_PARAM_NAME);
			if (StringUtils.hasText(tokenTypeHint) &&
					parameters.get(TOKEN_TYPE_HINT_PARAM_NAME).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, TOKEN_TYPE_HINT_PARAM_NAME);
			}

			return new OAuth2TokenRevocationAuthenticationToken(token, clientPrincipal, tokenTypeHint);
		}
	}
}
