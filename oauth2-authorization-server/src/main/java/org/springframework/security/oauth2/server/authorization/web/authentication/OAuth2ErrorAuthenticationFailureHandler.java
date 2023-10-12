/*
 * Copyright 2020-2023 the original author or authors.
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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * A default implementation of an {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
 * and returning the {@link OAuth2Error Error Response}.
 *
 * @author Dmitriy Dubson
 * @see AuthenticationFailureHandler
 * @since 1.2.0
 */
public final class OAuth2ErrorAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);

		if (authenticationException instanceof OAuth2AuthenticationException) {
			OAuth2Error error = ((OAuth2AuthenticationException) authenticationException).getError();
			this.errorHttpResponseConverter.write(error, null, httpResponse);
		} else {
			if (this.logger.isWarnEnabled()) {
				this.logger.warn(LogMessage.format("Authentication exception must be of type 'org.springframework.security.oauth2.core.OAuth2AuthenticationException'. Provided exception was '%s'", authenticationException.getClass().getName()));
			}
		}
	}

	/**
	 * Sets OAuth error HTTP message converter to write to upon authentication failure
	 *
	 * @param errorHttpResponseConverter the error HTTP message converter to set
	 */
	public void setErrorHttpResponseConverter(HttpMessageConverter<OAuth2Error> errorHttpResponseConverter) {
		this.errorHttpResponseConverter = errorHttpResponseConverter;
	}
}
