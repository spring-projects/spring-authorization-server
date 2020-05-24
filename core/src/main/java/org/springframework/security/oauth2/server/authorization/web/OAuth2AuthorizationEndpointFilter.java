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

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Authorization Request.
 *
 * @author Joe Grandja
 * @author Paurav Munshi
 * @since 0.0.1
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2Authorization
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for authorization requests.
	 */
	public static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final RequestMatcher authorizationEndpointMatcher;
	private final StringKeyGenerator codeGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		this(registeredClientRepository, authorizationService, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationEndpointUri the endpoint {@code URI} for authorization requests
	 */
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, String authorizationEndpointUri) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.authorizationEndpointMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.GET.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.authorizationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		// ---------------
		// Validate the request to ensure that all required parameters are present and valid
		// ---------------

		MultiValueMap<String, String> parameters = getParameters(request);
		String stateParameter = parameters.getFirst(OAuth2ParameterNames.STATE);

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) ||
				parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			OAuth2Error error = createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
			sendErrorResponse(request, response, error, stateParameter, null);	// when redirectUri is null then don't redirect
			return;
		}
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			OAuth2Error error = createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
			sendErrorResponse(request, response, error, stateParameter, null);	// when redirectUri is null then don't redirect
			return;
		} else if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			OAuth2Error error = createError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID);
			sendErrorResponse(request, response, error, stateParameter, null);	// when redirectUri is null then don't redirect
			return;
		}

		// redirect_uri (OPTIONAL)
		String redirectUriParameter = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		if (StringUtils.hasText(redirectUriParameter)) {
			if (!registeredClient.getRedirectUris().contains(redirectUriParameter) ||
					parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
				OAuth2Error error = createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
				sendErrorResponse(request, response, error, stateParameter, null);	// when redirectUri is null then don't redirect
				return;
			}
		} else if (registeredClient.getRedirectUris().size() != 1) {
			OAuth2Error error = createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
			sendErrorResponse(request, response, error, stateParameter, null);	// when redirectUri is null then don't redirect
			return;
		}

		String redirectUri = StringUtils.hasText(redirectUriParameter) ?
				redirectUriParameter : registeredClient.getRedirectUris().iterator().next();

		// response_type (REQUIRED)
		String responseType = parameters.getFirst(OAuth2ParameterNames.RESPONSE_TYPE);
		if (!StringUtils.hasText(responseType) ||
				parameters.get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
			OAuth2Error error = createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
			sendErrorResponse(request, response, error, stateParameter, redirectUri);
			return;
		} else if (!responseType.equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
			OAuth2Error error = createError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
			sendErrorResponse(request, response, error, stateParameter, redirectUri);
			return;
		}

		// ---------------
		// The request is valid - ensure the resource owner is authenticated
		// ---------------

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (!isPrincipalAuthenticated(principal)) {
			// Pass through the chain with the expectation that the authentication process
			// will commence via AuthenticationEntryPoint
			filterChain.doFilter(request, response);
			return;
		}

		String code = this.codeGenerator.generateKey();
		OAuth2AuthorizationRequest authorizationRequest = convertAuthorizationRequest(request);

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(principal.getName())
				.attribute(OAuth2AuthorizationAttributeNames.CODE, code)
				.attribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST, authorizationRequest)
				.build();

		this.authorizationService.save(authorization);

//		TODO security checks for code parameter
//		The authorization code MUST expire shortly after it is issued to mitigate the risk of leaks.
//		A maximum authorization code lifetime of 10 minutes is RECOMMENDED.
//		The client MUST NOT use the authorization code more than once.
//		If an authorization code is used more than once, the authorization server MUST deny the request
//		and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.
//		The authorization code is bound to the client identifier and redirection URI.

		sendAuthorizationResponse(request, response, authorizationRequest, code, redirectUri);
	}

	private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationRequest authorizationRequest, String code, String redirectUri) throws IOException {

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.CODE, code);
		if (StringUtils.hasText(authorizationRequest.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			OAuth2Error error, String state, String redirectUri) throws IOException {

		if (redirectUri == null) {
			// TODO Send default html error response
			response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
			return;
		}

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
		if (StringUtils.hasText(error.getDescription())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
		}
		if (StringUtils.hasText(error.getUri())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
		}
		if (StringUtils.hasText(state)) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

	private static OAuth2Error createError(String errorCode, String parameterName) {
		return new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc6749#section-4.1.2.1");
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null &&
				!AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
				principal.isAuthenticated();
	}

	private static OAuth2AuthorizationRequest convertAuthorizationRequest(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = getParameters(request);

		Set<String> scopes = Collections.emptySet();
		if (parameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
			scopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		return OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(request.getRequestURL().toString())
				.clientId(parameters.getFirst(OAuth2ParameterNames.CLIENT_ID))
				.redirectUri(parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI))
				.scopes(scopes)
				.state(parameters.getFirst(OAuth2ParameterNames.STATE))
				.additionalParameters(additionalParameters ->
						parameters.entrySet().stream()
								.filter(e -> !e.getKey().equals(OAuth2ParameterNames.RESPONSE_TYPE) &&
										!e.getKey().equals(OAuth2ParameterNames.CLIENT_ID) &&
										!e.getKey().equals(OAuth2ParameterNames.REDIRECT_URI) &&
										!e.getKey().equals(OAuth2ParameterNames.SCOPE) &&
										!e.getKey().equals(OAuth2ParameterNames.STATE))
								.forEach(e -> additionalParameters.put(e.getKey(), e.getValue().get(0))))
				.build();
	}

	private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
		parameterMap.forEach((key, values) -> {
			if (values.length > 0) {
				for (String value : values) {
					parameters.add(key, value);
				}
			}
		});
		return parameters;
	}
}
