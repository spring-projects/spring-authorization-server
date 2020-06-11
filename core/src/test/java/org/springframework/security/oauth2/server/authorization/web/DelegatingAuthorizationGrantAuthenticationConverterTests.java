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

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Alexey Nesterov
 */
public class DelegatingAuthorizationGrantAuthenticationConverterTests {

	private DelegatingAuthorizationGrantAuthenticationConverter authenticationConverter;
	private Converter<HttpServletRequest, Authentication> clientCredentialsConverterMock;

	@Before
	public void setUp() {
		clientCredentialsConverterMock = mock(Converter.class);
		Map<AuthorizationGrantType, Converter<HttpServletRequest, Authentication>> converters
				= Collections.singletonMap(AuthorizationGrantType.CLIENT_CREDENTIALS, clientCredentialsConverterMock);
		authenticationConverter = new DelegatingAuthorizationGrantAuthenticationConverter(converters);
	}

	@Test
	public void convertWhenAuthorizationGrantTypeSupportedThenConverterCalled() {
		MockHttpServletRequest request = MockMvcRequestBuilders
				.post("/oauth/token")
				.param("grant_type", "client_credentials")
				.buildRequest(new MockServletContext());

		OAuth2ClientAuthenticationToken expectedAuthentication = new OAuth2ClientAuthenticationToken("id", "secret");
		when(clientCredentialsConverterMock.convert(request)).thenReturn(expectedAuthentication);

		Authentication actualAuthentication = authenticationConverter.convert(request);

		verify(clientCredentialsConverterMock).convert(request);
		assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
	}

	@Test
	public void convertWhenAuthorizationGrantTypeNotSupportedThenNull() {
		MockHttpServletRequest request = MockMvcRequestBuilders
				.post("/oauth/token")
				.param("grant_type", "authorization_code")
				.buildRequest(new MockServletContext());

		Authentication actualAuthentication = authenticationConverter.convert(request);

		verifyNoInteractions(clientCredentialsConverterMock);
		assertThat(actualAuthentication).isNull();
	}

	@Test
	public void convertWhenNoAuthorizationGrantTypeThenNull() {
		MockHttpServletRequest request = MockMvcRequestBuilders
				.post("/oauth/token")
				.buildRequest(new MockServletContext());

		Authentication actualAuthentication = authenticationConverter.convert(request);

		verifyNoInteractions(clientCredentialsConverterMock);
		assertThat(actualAuthentication).isNull();
	}
}
