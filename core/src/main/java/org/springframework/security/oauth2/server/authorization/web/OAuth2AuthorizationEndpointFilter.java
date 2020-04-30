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
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Joe Grandja
 * @author Paurav Munshi
 * @since 0.0.1
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {

	private static final String DEFAULT_ENDPOINT = "/oauth2/authorize";

	private Converter<HttpServletRequest, OAuth2AuthorizationRequest> authorizationRequestConverter = new OAuth2AuthorizationRequestConverter();
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2AuthorizationService authorizationService;
	private StringKeyGenerator codeGenerator = new Base64StringKeyGenerator();
	private RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
	private RequestMatcher authorizationEndpointMatcher = new AntPathRequestMatcher(DEFAULT_ENDPOINT);

	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null.");
		Assert.notNull(authorizationService, "authorizationService cannot be null.");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	public final void setAuthorizationRequestConverter(
			Converter<HttpServletRequest, OAuth2AuthorizationRequest> authorizationRequestConverter) {
		Assert.notNull(authorizationRequestConverter, "authorizationRequestConverter cannot be set to null");
		this.authorizationRequestConverter = authorizationRequestConverter;
	}

	public final void setCodeGenerator(StringKeyGenerator codeGenerator) {
		Assert.notNull(codeGenerator, "codeGenerator cannot be set to null");
		this.codeGenerator = codeGenerator;
	}

	public final void setAuthorizationRedirectStrategy(RedirectStrategy authorizationRedirectStrategy) {
		Assert.notNull(authorizationRedirectStrategy, "authorizationRedirectStrategy cannot be set to null");
		this.authorizationRedirectStrategy = authorizationRedirectStrategy;
	}

	public final void setAuthorizationEndpointMatcher(RequestMatcher authorizationEndpointMatcher) {
		Assert.notNull(authorizationEndpointMatcher, "authorizationEndpointMatcher cannot be set to null");
		this.authorizationEndpointMatcher = authorizationEndpointMatcher;
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		boolean pathMatch = this.authorizationEndpointMatcher.matches(request);
		String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);
		boolean responseTypeMatch = OAuth2ParameterNames.CODE.equals(responseType);
		if (pathMatch && responseTypeMatch) {
			return false;
		}else {
			return true;
		}
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
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			client = fetchRegisteredClient(request);

			authorizationRequest = this.authorizationRequestConverter.convert(request);
			validateAuthorizationRequest(authorizationRequest, client);

			String code = this.codeGenerator.generateKey();
			authorization = buildOAuth2Authorization(auth, client, authorizationRequest, code);
			this.authorizationService.save(authorization);

			String redirectUri = getRedirectUri(authorizationRequest, client);
			sendCodeOnSuccess(request, response, authorizationRequest, redirectUri, code);
		}
		catch(OAuth2AuthorizationException authorizationException) {
			OAuth2Error authorizationError = authorizationException.getError();

			if (authorizationError.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
					|| authorizationError.getErrorCode().equals(OAuth2ErrorCodes.ACCESS_DENIED)) {
				sendErrorInResponse(response, authorizationError);
			}
			else if (authorizationError.getErrorCode().equals(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE)
					|| authorizationError.getErrorCode().equals(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)) {
				String redirectUri = getRedirectUri(authorizationRequest, client);
				sendErrorInRedirect(request, response, authorizationRequest, authorizationError, redirectUri);
			}
			else {
				throw new ServletException(authorizationException);
			}
		}

	}

	private void checkUserAuthenticated() {
		Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
		if (currentAuth==null || !currentAuth.isAuthenticated()) {
			throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
		}
	}

	private RegisteredClient fetchRegisteredClient(HttpServletRequest request) throws OAuth2AuthorizationException {
		String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
		if (StringUtils.isEmpty(clientId)) {
			throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}

		RegisteredClient client = this.registeredClientRepository.findByClientId(clientId);
		if (client==null) {
			throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
		}

		boolean isAuthorizationGrantAllowed = Stream.of(client.getAuthorizationGrantTypes())
				.anyMatch(grantType -> grantType.contains(AuthorizationGrantType.AUTHORIZATION_CODE));
		if (!isAuthorizationGrantAllowed) {
			throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
		}

		return client;

	}

	private OAuth2Authorization buildOAuth2Authorization(Authentication auth, RegisteredClient client,
			OAuth2AuthorizationRequest authorizationRequest, String code) {
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
					.principalName(auth.getPrincipal().toString())
					.attribute(TokenType.AUTHORIZATION_CODE.getValue(), code)
					.attributes(attirbutesMap -> attirbutesMap.putAll(authorizationRequest.getAttributes()))
					.build();

		return authorization;
	}


	private void validateAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, RegisteredClient client) {
		String redirectUri = authorizationRequest.getRedirectUri();
		if (StringUtils.isEmpty(redirectUri) && client.getRedirectUris().size() > 1) {
			throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}
		if (!StringUtils.isEmpty(redirectUri) && !client.getRedirectUris().contains(redirectUri)) {
			throw new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}
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
		if (!StringUtils.isEmpty(authorizationRequest.getState())) {
			redirectUriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		}

		String finalRedirectUri = redirectUriBuilder.toUriString();
		this.authorizationRedirectStrategy.sendRedirect(request, response, finalRedirectUri);
	}

	private void sendErrorInResponse(HttpServletResponse response, OAuth2Error authorizationError) throws IOException {
		int errorStatus = -1;
		String errorCode = authorizationError.getErrorCode();
		if (errorCode.equals(OAuth2ErrorCodes.ACCESS_DENIED)) {
			errorStatus=HttpStatus.FORBIDDEN.value();
		}
		else {
			errorStatus=HttpStatus.INTERNAL_SERVER_ERROR.value();
		}
		response.sendError(errorStatus, authorizationError.getErrorCode());
	}

	private void sendErrorInRedirect(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationRequest authorizationRequest, OAuth2Error authorizationError,
			String redirectUri) throws IOException {
		UriComponentsBuilder redirectUriBuilder = UriComponentsBuilder.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.ERROR, authorizationError.getErrorCode());

		if (!StringUtils.isEmpty(authorizationRequest.getState())) {
			redirectUriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		}

		String finalRedirectURI = redirectUriBuilder.toUriString();
		this.authorizationRedirectStrategy.sendRedirect(request, response, finalRedirectURI);
	}
}
