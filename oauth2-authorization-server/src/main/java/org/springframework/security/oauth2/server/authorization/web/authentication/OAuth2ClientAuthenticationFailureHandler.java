/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthenticationFailureHandler} used for handling a failed
 * authentication attempt by an OAuth 2.0 Client and delegating to an
 * {@link AuthenticationEntryPoint} based on the {@link ClientAuthenticationMethod} used
 * by the client.
 *
 * @author Joe Grandja
 * @since 1.5
 * @see AuthenticationFailureHandler
 * @see AuthenticationEntryPoint
 * @see OAuth2ClientAuthenticationFilter
 * @see OAuth2ClientAuthenticationException
 */
public final class OAuth2ClientAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final Map<ClientAuthenticationMethod, AuthenticationEntryPoint> authenticationEntryPoints;

	private AuthenticationEntryPoint defaultAuthenticationEntryPoint = new DefaultAuthenticationEntryPoint();

	public OAuth2ClientAuthenticationFailureHandler() {
		this.authenticationEntryPoints = new HashMap<>();
		BasicAuthenticationEntryPoint basicAuthenticationEntryPoint = new BasicAuthenticationEntryPoint();
		basicAuthenticationEntryPoint.setRealmName("default");
		this.authenticationEntryPoints.put(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				basicAuthenticationEntryPoint);
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		AuthenticationEntryPoint authenticationEntryPoint = this.defaultAuthenticationEntryPoint;
		if (authenticationException instanceof OAuth2ClientAuthenticationException clientAuthenticationException) {
			OAuth2ClientAuthenticationToken clientAuthentication = clientAuthenticationException
				.getClientAuthentication();
			AuthenticationEntryPoint clientAuthenticationMethodEntryPoint = this.authenticationEntryPoints
				.get(clientAuthentication.getClientAuthenticationMethod());
			if (clientAuthenticationMethodEntryPoint != null) {
				// Override the default
				authenticationEntryPoint = clientAuthenticationMethodEntryPoint;
			}
		}
		authenticationEntryPoint.commence(request, response, authenticationException);
	}

	/**
	 * Sets the {@link AuthenticationEntryPoint} used for the specified
	 * {@link ClientAuthenticationMethod}.
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint}
	 * @param clientAuthenticationMethod the {@link ClientAuthenticationMethod}
	 */
	public void setAuthenticationEntryPointFor(AuthenticationEntryPoint authenticationEntryPoint,
			ClientAuthenticationMethod clientAuthenticationMethod) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		Assert.notNull(clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
		this.authenticationEntryPoints.put(clientAuthenticationMethod, authenticationEntryPoint);
	}

	/**
	 * Sets the default {@link AuthenticationEntryPoint} used when unable to determine the
	 * {@link ClientAuthenticationMethod} used by the client.
	 * @param defaultAuthenticationEntryPoint the default {@link AuthenticationEntryPoint}
	 */
	public void setDefaultAuthenticationEntryPoint(AuthenticationEntryPoint defaultAuthenticationEntryPoint) {
		Assert.notNull(defaultAuthenticationEntryPoint, "defaultAuthenticationEntryPoint cannot be null");
		this.defaultAuthenticationEntryPoint = defaultAuthenticationEntryPoint;
	}

	private static final class DefaultAuthenticationEntryPoint implements AuthenticationEntryPoint {

		private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException exception) throws IOException {
			OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
			ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
			if (OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
				httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
			}
			else {
				httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
			}
			// We don't want to reveal too much information to the caller
			// so just return the error code
			OAuth2Error errorResponse = new OAuth2Error(error.getErrorCode());
			this.errorHttpResponseConverter.write(errorResponse, null, httpResponse);
		}

	}

}
