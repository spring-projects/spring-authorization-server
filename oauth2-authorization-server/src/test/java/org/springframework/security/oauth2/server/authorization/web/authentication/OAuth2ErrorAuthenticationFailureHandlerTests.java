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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2ErrorAuthenticationFailureHandler}
 *
 * @author Dmitriy Dubson
 */
public class OAuth2ErrorAuthenticationFailureHandlerTests {

	private HttpMessageConverter<OAuth2Error> errorHttpMessageConverter;

	private HttpServletRequest request;

	private HttpServletResponse response;

	@BeforeEach
	@SuppressWarnings("unchecked")
	public void setUp() {
		errorHttpMessageConverter = (HttpMessageConverter<OAuth2Error>) mock(HttpMessageConverter.class);
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
	}

	@Test
	public void onAuthenticationFailure() throws IOException, ServletException {
		OAuth2Error invalidRequestError = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
		AuthenticationException authenticationException = new OAuth2AuthenticationException(invalidRequestError);
		OAuth2ErrorAuthenticationFailureHandler handler = new OAuth2ErrorAuthenticationFailureHandler();
		handler.setErrorHttpResponseConverter(errorHttpMessageConverter);

		handler.onAuthenticationFailure(request, response, authenticationException);

		verify(errorHttpMessageConverter).write(eq(invalidRequestError), isNull(), any(ServletServerHttpResponse.class));
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
	}

	@Test
	public void onAuthenticationFailure_ifExceptionProvidedIsNotOAuth2AuthenticationException() throws ServletException, IOException {
		OAuth2ErrorAuthenticationFailureHandler handler = new OAuth2ErrorAuthenticationFailureHandler();
		handler.setErrorHttpResponseConverter(errorHttpMessageConverter);

		handler.onAuthenticationFailure(request, response, new BadCredentialsException("Not a valid exception."));

		verifyNoInteractions(errorHttpMessageConverter);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
	}

}
