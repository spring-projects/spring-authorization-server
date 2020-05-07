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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

/**
 * This {@code Filter} is used by the client to obtain an access token by presenting
 * its authorization grant.
 *
 * <p>
 * It converts the OAuth 2.0 Access Token Request to {@link OAuth2AuthorizationCodeAuthenticationToken},
 * which is then authenticated by the {@link AuthenticationManager} and gets back
 * {@link OAuth2AccessTokenAuthenticationToken} which has the {@link OAuth2AccessToken} if the request
 * was successfully authenticated. The {@link OAuth2AccessToken} is then updated in the in-flight {@link OAuth2Authorization}
 * and sent back to the client. In case the authentication fails, an HTTP 401 (Unauthorized) response is returned.
 *
 * <p>
 * By default, this {@code Filter} responds to access token requests
 * at the {@code URI} {@code /oauth2/token} and {@code HttpMethod} {@code POST}
 * using the default {@link AntPathRequestMatcher}.
 *
 * <p>
 * The default base {@code URI} {@code /oauth2/token} may be overridden
 * via the constructor {@link #OAuth2TokenEndpointFilter(OAuth2AuthorizationService, AuthenticationManager, String)}.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 */
public class OAuth2TokenEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for access token requests.
	 */
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private Converter<HttpServletRequest, Authentication> authorizationGrantConverter = this::convert;
	private AuthenticationManager authenticationManager;
	private OAuth2AuthorizationService authorizationService;
	private RequestMatcher uriMatcher;
	private ObjectMapper objectMapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);

	/**
	 * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
	 *
	 * @param authorizationService  the authorization service implementation
	 * @param authenticationManager the authentication manager implementation
	 */
	public OAuth2TokenEndpointFilter(OAuth2AuthorizationService authorizationService, AuthenticationManager authenticationManager) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		this.authorizationService = authorizationService;
		this.uriMatcher = new AntPathRequestMatcher(DEFAULT_TOKEN_ENDPOINT_URI, HttpMethod.POST.name());
	}

	/**
	 * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
	 *
	 * @param authorizationService  the authorization service implementation
	 * @param authenticationManager the authentication manager implementation
	 * @param tokenEndpointUri      the token endpoint's uri
	 */
	public OAuth2TokenEndpointFilter(OAuth2AuthorizationService authorizationService, AuthenticationManager authenticationManager,
			String tokenEndpointUri) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(tokenEndpointUri, "tokenEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.authorizationService = authorizationService;
		this.uriMatcher = new AntPathRequestMatcher(tokenEndpointUri, HttpMethod.POST.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (uriMatcher.matches(request)) {
			try {
				if (validateAccessTokenRequest(request)) {
					OAuth2AuthorizationCodeAuthenticationToken authCodeAuthToken =
							(OAuth2AuthorizationCodeAuthenticationToken) authorizationGrantConverter.convert(request);
					OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationToken =
							(OAuth2AccessTokenAuthenticationToken) authenticationManager.authenticate(authCodeAuthToken);
					if (accessTokenAuthenticationToken.isAuthenticated()) {
						OAuth2Authorization authorization = authorizationService
								.findByTokenAndTokenType(authCodeAuthToken.getCode(), TokenType.AUTHORIZATION_CODE);
						authorization.setAccessToken(accessTokenAuthenticationToken.getAccessToken());
						authorizationService.save(authorization);
						writeSuccessResponse(response, accessTokenAuthenticationToken.getAccessToken());
					} else {
						throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
					}
				}
			} catch (OAuth2AuthenticationException exception) {
				SecurityContextHolder.clearContext();
				writeFailureResponse(response, exception.getError());
			}
		} else {
			filterChain.doFilter(request, response);
		}
	}

	private boolean validateAccessTokenRequest(HttpServletRequest request) {
		if (StringUtils.isEmpty(request.getParameter(OAuth2ParameterNames.CODE))
				|| StringUtils.isEmpty(request.getParameter(OAuth2ParameterNames.REDIRECT_URI))
				|| StringUtils.isEmpty(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		} else if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE));
		}
		return true;
	}

	private OAuth2AuthorizationCodeAuthenticationToken convert(HttpServletRequest request) {
		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
		return new OAuth2AuthorizationCodeAuthenticationToken(
				request.getParameter(OAuth2ParameterNames.CODE),
				clientPrincipal,
				request.getParameter(OAuth2ParameterNames.REDIRECT_URI)
		);
	}

	private void writeSuccessResponse(HttpServletResponse response, OAuth2AccessToken body) throws IOException {
		try (Writer out = response.getWriter()) {
			response.setStatus(HttpStatus.OK.value());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding("UTF-8");
			response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
			response.setHeader(HttpHeaders.PRAGMA, "no-cache");
			out.write(objectMapper.writeValueAsString(body));
		}
	}

	private void writeFailureResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		try (Writer out = response.getWriter()) {
			if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_CLIENT)) {
				response.setStatus(HttpStatus.UNAUTHORIZED.value());
			} else {
				response.setStatus(HttpStatus.BAD_REQUEST.value());
			}
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding("UTF-8");
			out.write(objectMapper.writeValueAsString(error));
		}
	}
}
