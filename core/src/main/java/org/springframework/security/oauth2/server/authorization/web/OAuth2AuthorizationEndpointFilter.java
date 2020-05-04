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

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.util.AuthorizationCodeKeyGenerator;
import org.springframework.security.oauth2.server.authorization.util.OAuth2AuthorizationServerMessages;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Joe Grandja
 * @author Paurav Munshi
 * @since 0.0.1
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {

	private Converter<HttpServletRequest, OAuth2AuthorizationRequest> authorizationRequestConverter;
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2AuthorizationService authorizationService;
	private StringKeyGenerator codeGenerator;
	private RedirectStrategy authorizationRedirectStrategy;
	private RequestMatcher authorizationEndpiontMatcher;

	private static final String DEFAULT_ENDPOINT = "/oauth2/authorize";

	private static final OAuth2Error CLIENT_ID_ABSENT_ERROR = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2AuthorizationServerMessages.REQUEST_MISSING_CLIENT_ID, null);
	private static final OAuth2Error REDIRECT_URI_REQUIRED = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2AuthorizationServerMessages.REDIRECT_URI_MANDATORY_FOR_CLIENT, null);
	private static final OAuth2Error CLIENT_ID_NOT_FOUND_ERROR = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2AuthorizationServerMessages.CLIENT_ID_NOT_FOUND, null);
	private static final OAuth2Error USER_NOT_AUTHENTICATED_ERROR = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2AuthorizationServerMessages.USER_NOT_AUTHENTICATED, null);
	private static final OAuth2Error AUTHZ_CODE_NOT_SUPPORTED_ERROR = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2AuthorizationServerMessages.CLIENT_ID_UNAUTHORIZED_FOR_CODE, null);
	private static final OAuth2Error RESPONSE_TYPE_NOT_FOUND_ERROR = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2AuthorizationServerMessages.RESPONSE_TYPE_MISSING_OR_INVALID, null);



	public OAuth2AuthorizationEndpointFilter() {
		authorizationEndpiontMatcher = new AntPathRequestMatcher(DEFAULT_ENDPOINT);
		authorizationRequestConverter  = new OAuth2AuthorizationRequestConverter();
		codeGenerator  = new AuthorizationCodeKeyGenerator();
		authorizationRedirectStrategy  = new DefaultRedirectStrategy();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		RegisteredClient client = null;
		OAuth2AuthorizationRequest authorizationRequest = null;
		OAuth2Authorization authorization = null;

		try {
			checkUserAuthenticated();
			client = fetchRegisteredClient(request);

			authorizationRequest = authorizationRequestConverter.convert(request);
			validateAuthorizationRequest(request, client);

			String code = codeGenerator.generateKey();
			authorization = buildOAuth2Authorization(client, authorizationRequest, code);
			authorizationService.save(authorization);

			String redirectUri = getRedirectUri(authorizationRequest, client);
			sendCodeOnSuccess(request, response, authorizationRequest, redirectUri, code);
		}catch(OAuth2AuthorizationException authorizationException) {
			OAuth2Error authorizationError = authorizationException.getError();

			if (authorizationError.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
					|| authorizationError.getErrorCode().equals(OAuth2ErrorCodes.ACCESS_DENIED)) {
				sendErrorInResponse(response, authorizationError);
			}
			else if (authorizationError.getErrorCode().equals(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE)
					|| authorizationError.getErrorCode().equals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)) {
				String redirectUri = getRedirectUri(authorizationRequest, client);
				sendErrorInRedirect(request, response, authorizationRequest, authorizationError, redirectUri);
			}else {
				throw new ServletException(authorizationException);
			}
		}

	}

	protected void checkUserAuthenticated() {
		Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
		if (currentAuth==null || !currentAuth.isAuthenticated())
			throw new OAuth2AuthorizationException(USER_NOT_AUTHENTICATED_ERROR);
	}

	protected RegisteredClient fetchRegisteredClient(HttpServletRequest request) throws OAuth2AuthorizationException {
		String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
		if (StringUtils.isEmpty(clientId))
			throw new OAuth2AuthorizationException(CLIENT_ID_ABSENT_ERROR);

		RegisteredClient client = registeredClientRepository.findByClientId(clientId);
		if (client==null)
			throw new OAuth2AuthorizationException(CLIENT_ID_NOT_FOUND_ERROR);

		boolean isAuthoirzationGrantAllowed = Stream.of(client.getAuthorizationGrantTypes())
				.anyMatch(grantType -> grantType.contains(AuthorizationGrantType.AUTHORIZATION_CODE));
			if (!isAuthoirzationGrantAllowed)
				throw new OAuth2AuthorizationException(AUTHZ_CODE_NOT_SUPPORTED_ERROR);

		return client;

	}

	protected OAuth2Authorization buildOAuth2Authorization(RegisteredClient client,
			OAuth2AuthorizationRequest authorizationRequest, String code) {
		OAuth2Authorization authorization = OAuth2Authorization.createBuilder()
					.clientId(authorizationRequest.getClientId())
					.addAttribute(OAuth2ParameterNames.CODE, code)
					.addAttribute(OAuth2Authorization.ISSUED_AT, Instant.now())
					.addAttribute(OAuth2Authorization.CODE_USED, new AtomicBoolean(false))
					.addAttribute(OAuth2ParameterNames.SCOPE, Optional.ofNullable(authorizationRequest.getScopes())
							.filter(scopes -> !scopes.isEmpty()).orElse(client.getScopes()))
					.build();

		return authorization;
	}


	protected void validateAuthorizationRequest(HttpServletRequest request, RegisteredClient client) {
		String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);
		if (StringUtils.isEmpty(responseType)
				|| !responseType.equals(OAuth2AuthorizationResponseType.CODE.getValue()))
			throw new OAuth2AuthorizationException(RESPONSE_TYPE_NOT_FOUND_ERROR);

		String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
		if (StringUtils.isEmpty(redirectUri) && client.getRedirectUris().size() > 1)
			throw new OAuth2AuthorizationException(REDIRECT_URI_REQUIRED);
	}

	private String getRedirectUri(OAuth2AuthorizationRequest authorizationRequest, RegisteredClient client) {
		return !StringUtils.isEmpty(authorizationRequest.getRedirectUri())
		? authorizationRequest.getRedirectUri()
		: client.getRedirectUris().stream().findFirst().get();
	}

	private void sendCodeOnSuccess(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationRequest authorizationRequest, String redirectUri, String code) throws IOException {
		UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.CODE, code);
		if (!StringUtils.isEmpty(authorizationRequest.getState()))
			redirectUriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState());

		String finalRedirectUri = redirectUriBuilder.toUriString();
		this.authorizationRedirectStrategy.sendRedirect(request, response, finalRedirectUri);
	}

	private void sendErrorInResponse(HttpServletResponse response, OAuth2Error authorizationError) throws IOException {
		int errorStatus = -1;
		String errorCode = authorizationError.getErrorCode();
		if (errorCode.equals(OAuth2ErrorCodes.ACCESS_DENIED))
			errorStatus=HttpStatus.FORBIDDEN.value();
		else errorStatus=HttpStatus.INTERNAL_SERVER_ERROR.value();
		response.sendError(errorStatus, authorizationError.getErrorCode()+":"+authorizationError.getDescription());
	}

	private void sendErrorInRedirect(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationRequest authorizationRequest, OAuth2Error authorizationError,
			String redirectUri) throws IOException {
		UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.ERROR, authorizationError.getErrorCode())
				.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, authorizationError.getDescription());

		if (!StringUtils.isEmpty(authorizationRequest.getState()))
			redirectUriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState());

		String finalRedirectURI = redirectUriBuilder.toUriString();
		this.authorizationRedirectStrategy.sendRedirect(request, response, finalRedirectURI);
	}

	public Converter<HttpServletRequest, OAuth2AuthorizationRequest> getAuthorizationRequestConverter() {
		return authorizationRequestConverter;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return !authorizationEndpiontMatcher.matches(request);
	}

	public void setAuthorizationRequestConverter(
			Converter<HttpServletRequest, OAuth2AuthorizationRequest> authorizationRequestConverter) {
		this.authorizationRequestConverter = authorizationRequestConverter;
	}

	public RegisteredClientRepository getRegisteredClientRepository() {
		return registeredClientRepository;
	}

	public void setRegisteredClientRepository(RegisteredClientRepository registeredClientRepository) {
		this.registeredClientRepository = registeredClientRepository;
	}

	public OAuth2AuthorizationService getAuthorizationService() {
		return authorizationService;
	}

	public void setAuthorizationService(OAuth2AuthorizationService authorizationService) {
		this.authorizationService = authorizationService;
	}

	public StringKeyGenerator getCodeGenerator() {
		return codeGenerator;
	}

	public void setCodeGenerator(StringKeyGenerator codeGenerator) {
		this.codeGenerator = codeGenerator;
	}

	public RedirectStrategy getAuthorizationRedirectStrategy() {
		return authorizationRedirectStrategy;
	}

	public void setAuthorizationRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.authorizationRedirectStrategy = redirectStrategy;
	}

}
