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
package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.springframework.security.oauth2.core.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} for the OAuth 2.0 Token Introspection endpoint.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @see OAuth2TokenIntrospectionAuthenticationProvider
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2">Section 2 Introspection Endpoint</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section 2.1 Introspection Request</a>
 * @since 0.1.1
 */
public class OAuth2TokenIntrospectionEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for token introspection requests.
	 */
	public static final String DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI = "/oauth2/introspect";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher tokenIntrospectionEndpointMatcher;
	private final Converter<HttpServletRequest, Authentication> tokenIntrospectionAuthenticationConverter =
			new DefaultTokenIntrospectionAuthenticationConverter();
	private final HttpMessageConverter<OAuth2TokenIntrospection> tokenIntrospectionHttpResponseConverter =
			new OAuth2TokenIntrospectionHttpMessageConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2TokenIntrospectionEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param tokenIntrospectionEndpointUri the endpoint {@code URI} for token introspection requests
	 */
	public OAuth2TokenIntrospectionEndpointFilter(AuthenticationManager authenticationManager,
			String tokenIntrospectionEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(tokenIntrospectionEndpointUri, "tokenIntrospectionEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.tokenIntrospectionEndpointMatcher = new AntPathRequestMatcher(
				tokenIntrospectionEndpointUri, HttpMethod.POST.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenIntrospectionEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication =
					(OAuth2TokenIntrospectionAuthenticationToken) this.tokenIntrospectionAuthenticationConverter.convert(request);

			OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthenticationResult =
					(OAuth2TokenIntrospectionAuthenticationToken) this.authenticationManager.authenticate(tokenIntrospectionAuthentication);

			OAuth2TokenIntrospection tokenClaims = tokenIntrospectionAuthenticationResult.getTokenClaims();
			sendTokenIntrospectionResponse(response, tokenClaims);

		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			sendErrorResponse(response, ex.getError());
		}
	}

	private void sendTokenIntrospectionResponse(HttpServletResponse response, OAuth2TokenIntrospection tokenClaims) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.tokenIntrospectionHttpResponseConverter.write(tokenClaims, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Token Introspection Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc7662#section-2.1");
		throw new OAuth2AuthenticationException(error);
	}

	private static class DefaultTokenIntrospectionAuthenticationConverter
			implements Converter<HttpServletRequest, Authentication> {

		@Override
		public Authentication convert(HttpServletRequest request) {
			Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

			MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

			// token (REQUIRED)
			String token = parameters.getFirst(OAuth2ParameterNames2.TOKEN);
			if (!StringUtils.hasText(token) ||
					parameters.get(OAuth2ParameterNames2.TOKEN).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames2.TOKEN);
			}

			// token_type_hint (OPTIONAL)
			String tokenTypeHint = parameters.getFirst(OAuth2ParameterNames2.TOKEN_TYPE_HINT);
			if (StringUtils.hasText(tokenTypeHint) &&
					parameters.get(OAuth2ParameterNames2.TOKEN_TYPE_HINT).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames2.TOKEN_TYPE_HINT);
			}

			// @formatter:off
			Map<String, Object> additionalParameters = parameters
					.entrySet()
					.stream()
					.filter(e -> !e.getKey().equals(OAuth2ParameterNames2.TOKEN) &&
							!e.getKey().equals(OAuth2ParameterNames2.TOKEN_TYPE_HINT))
					.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get(0)));
			// @formatter:on

			return new OAuth2TokenIntrospectionAuthenticationToken(
					token, clientPrincipal, tokenTypeHint, additionalParameters);
		}
	}
}
