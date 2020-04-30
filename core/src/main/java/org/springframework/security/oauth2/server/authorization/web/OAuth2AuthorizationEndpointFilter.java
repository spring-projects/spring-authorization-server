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
import java.util.Optional;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
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
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * @author Joe Grandja
 * @author Paurav Munshi
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
	private Converter<HttpServletRequest, OAuth2AuthorizationRequest> authorizationRequestConverter;
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2AuthorizationService authorizationService;
	private StringKeyGenerator codeGenerator;
	private RedirectStrategy authorizationRedirectStrategy;
	
	private static final OAuth2Error CLIENT_ID_ABSENT_ERROR = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,"Request does not contain client id parameter",null);
	private static final OAuth2Error CLIENT_ID_NOT_FOUND_ERROR = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,"Can't validate the client id provided with the request",null);
	private static final OAuth2Error RESPONSE_TYPE_NOT_FOUND_ERROR = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE,"Response type should be present and it should be 'code'",null);
	private static final OAuth2Error AUTHZ_CODE_NOT_SUPPORTED_ERROR = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE,"The provided client does not support Authorization Code grant",null);
	
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		RegisteredClient client = null;
		OAuth2AuthorizationRequest authorizationRequest = null;
		OAuth2Authorization authorization = null;
		
		try {
			client = fetchRegisteredClient(request);
			
			authorizationRequest = authorizationRequestConverter.convert(request);
			validateAuthorizationRequest(authorizationRequest,client);
			
			String code = codeGenerator.generateKey();
			authorization = buildOAuth2Authorization(client,authorizationRequest,code);
			authorizationService.save(authorization);
			
			this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getRedirectUri());
		}catch(OAuth2AuthorizationException authorizationException) {
			OAuth2Error authorizationError = authorizationException.getError();
			
			if(authorizationError.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
					|| authorizationError.getErrorCode().equals(OAuth2ErrorCodes.ACCESS_DENIED)
					|| authorizationError.getErrorCode().equals(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE))
				sendErrorInResponse(response, authorizationError);
			
			if(authorizationError.getErrorCode().equals(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE))
				sendErrorInRedirect(request, response, authorizationError, authorizationRequest.getRedirectUri());
		}

	}
	
	private RegisteredClient fetchRegisteredClient(HttpServletRequest request) throws OAuth2AuthorizationException {
		String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
		if(StringUtils.isEmpty(clientId))
			throw new OAuth2AuthorizationException(CLIENT_ID_ABSENT_ERROR);
		
		RegisteredClient client = registeredClientRepository.findByClientId(clientId);
		if(client==null) 
			throw new OAuth2AuthorizationException(CLIENT_ID_NOT_FOUND_ERROR);
		
		boolean isAuthoirzationGrantAllowed = Stream.of(client.getAuthorizationGrantTypes())
				.anyMatch(grantType -> grantType.equals(AuthorizationGrantType.AUTHORIZATION_CODE));
			if(!isAuthoirzationGrantAllowed)
				throw new OAuth2AuthorizationException(AUTHZ_CODE_NOT_SUPPORTED_ERROR);
			
		return client;
		
	}
	
	private OAuth2Authorization buildOAuth2Authorization(RegisteredClient client, 
			OAuth2AuthorizationRequest authorizationRequest, String code) {
		OAuth2Authorization authorization = OAuth2Authorization.createBuilder()
					.clientId(authorizationRequest.getClientId())
					.addAttribute(OAuth2ParameterNames.CODE, code)
					.build();
		
		return authorization;
	}
	
	
	private void validateAuthorizationRequest(OAuth2AuthorizationRequest authzRequest, RegisteredClient client) {
		OAuth2AuthorizationResponseType responseType = Optional.ofNullable(authzRequest.getResponseType())
						.orElseThrow(() -> new OAuth2AuthorizationException(RESPONSE_TYPE_NOT_FOUND_ERROR));
		
		if(!responseType.equals(OAuth2AuthorizationResponseType.CODE))
			throw new OAuth2AuthorizationException(RESPONSE_TYPE_NOT_FOUND_ERROR);
			
	}
	
	private void sendErrorInResponse(HttpServletResponse response, OAuth2Error authorizationError) throws IOException {
		response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), authorizationError.getErrorCode()+":"+authorizationError.getDescription());
	}
	
	private void sendErrorInRedirect(HttpServletRequest request, HttpServletResponse response, OAuth2Error authorizationError, String redirectUri) throws IOException {
		String finalRedirectURI = new StringBuilder(redirectUri)
				.append("?").append("error_code=").append(authorizationError.getErrorCode())
				.append("&").append("error_description=").append(authorizationError.getDescription())
				.toString();
		
		this.authorizationRedirectStrategy.sendRedirect(request, response, finalRedirectURI);
	}

	public Converter<HttpServletRequest, OAuth2AuthorizationRequest> getAuthorizationRequestConverter() {
		return authorizationRequestConverter;
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
	
	public void getAuthorizationRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.authorizationRedirectStrategy = redirectStrategy;
	}
	
}
