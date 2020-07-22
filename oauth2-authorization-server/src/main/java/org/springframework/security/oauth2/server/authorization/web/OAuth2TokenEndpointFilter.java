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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
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
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Access Token Request.
 *
 * <p>
 * It converts the OAuth 2.0 Access Token Request to an {@link OAuth2AuthorizationCodeAuthenticationToken},
 * which is then authenticated by the {@link AuthenticationManager}.
 * If the authentication succeeds, the {@link AuthenticationManager} returns an
 * {@link OAuth2AccessTokenAuthenticationToken}, which contains
 * the {@link OAuth2AccessToken} that is returned in the response.
 * In case of any error, an {@link OAuth2Error} is returned in the response.
 *
 * <p>
 * By default, this {@code Filter} responds to access token requests
 * at the {@code URI} {@code /oauth2/token} and {@code HttpMethod} {@code POST}.
 *
 * <p>
 * The default endpoint {@code URI} {@code /oauth2/token} may be overridden
 * via the constructor {@link #OAuth2TokenEndpointFilter(AuthenticationManager, OAuth2AuthorizationService, String)}.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @since 0.0.1
 * @see AuthenticationManager
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public class OAuth2TokenEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for access token requests.
	 */
	public static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private final AuthenticationManager authenticationManager;
	private final OAuth2AuthorizationService authorizationService;
	private final RequestMatcher tokenEndpointMatcher;
	private final Converter<HttpServletRequest, Authentication> authorizationGrantAuthenticationConverter;
	private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();

	/**
	 * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param authorizationService the authorization service
	 */
	public OAuth2TokenEndpointFilter(AuthenticationManager authenticationManager,
			OAuth2AuthorizationService authorizationService) {
		this(authenticationManager, authorizationService, DEFAULT_TOKEN_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param authorizationService the authorization service
	 * @param tokenEndpointUri the endpoint {@code URI} for access token requests
	 */
	public OAuth2TokenEndpointFilter(AuthenticationManager authenticationManager,
			OAuth2AuthorizationService authorizationService, String tokenEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.hasText(tokenEndpointUri, "tokenEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.authorizationService = authorizationService;
		this.tokenEndpointMatcher = new AntPathRequestMatcher(tokenEndpointUri, HttpMethod.POST.name());
		Map<AuthorizationGrantType, Converter<HttpServletRequest, Authentication>> converters = new HashMap<>();
		converters.put(AuthorizationGrantType.AUTHORIZATION_CODE, new AuthorizationCodeAuthenticationConverter());
		converters.put(AuthorizationGrantType.CLIENT_CREDENTIALS, new ClientCredentialsAuthenticationConverter());
		this.authorizationGrantAuthenticationConverter = new DelegatingAuthorizationGrantAuthenticationConverter(converters);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			String[] grantTypes = request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE);
			if (grantTypes == null || grantTypes.length != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.GRANT_TYPE);
			}

			Authentication authorizationGrantAuthentication = this.authorizationGrantAuthenticationConverter.convert(request);
			if (authorizationGrantAuthentication == null) {
				throwError(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, OAuth2ParameterNames.GRANT_TYPE);
			}

			OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
					(OAuth2AccessTokenAuthenticationToken) this.authenticationManager.authenticate(authorizationGrantAuthentication);
			sendAccessTokenResponse(response, accessTokenAuthentication.getAccessToken());

		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			sendErrorResponse(response, ex.getError());
		}
	}

	private void sendAccessTokenResponse(HttpServletResponse response, OAuth2AccessToken accessToken) throws IOException {
		OAuth2AccessTokenResponse.Builder builder =
				OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
						.tokenType(accessToken.getTokenType())
						.scopes(accessToken.getScopes());
		if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
			builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
		}
		OAuth2AccessTokenResponse accessTokenResponse = builder.build();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc6749#section-5.2");
		throw new OAuth2AuthenticationException(error);
	}

	private static class AuthorizationCodeAuthenticationConverter implements Converter<HttpServletRequest, Authentication> {

		@Override
		public Authentication convert(HttpServletRequest request) {
			// grant_type (REQUIRED)
			String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
			if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
				return null;
			}

			MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

			// client_id (REQUIRED)
			String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
			Authentication clientPrincipal = null;
			if (StringUtils.hasText(clientId)) {
				if (parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
				}
			} else {
				clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
			}

			// code (REQUIRED)
			String code = parameters.getFirst(OAuth2ParameterNames.CODE);
			if (!StringUtils.hasText(code) ||
					parameters.get(OAuth2ParameterNames.CODE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CODE);
			}

			// redirect_uri (REQUIRED)
			// Required only if the "redirect_uri" parameter was included in the authorization request
			String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
			if (StringUtils.hasText(redirectUri) &&
					parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
			}

			return clientPrincipal != null ?
					new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri) :
					new OAuth2AuthorizationCodeAuthenticationToken(code, clientId, redirectUri);
		}
	}

	private static class ClientCredentialsAuthenticationConverter implements Converter<HttpServletRequest, Authentication> {

		@Override
		public Authentication convert(HttpServletRequest request) {
			// grant_type (REQUIRED)
			String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
			if (!AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantType)) {
				return null;
			}

			Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

			MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

			// scope (OPTIONAL)
			String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
			if (StringUtils.hasText(scope) &&
					parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
			}
			if (StringUtils.hasText(scope)) {
				Set<String> requestedScopes = new HashSet<>(
						Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
				return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, requestedScopes);
			}

			return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal);
		}
	}
}
