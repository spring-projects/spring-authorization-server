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

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DelegatingAuthorizationGrantAuthenticationConverter}.
 *
 * @author Alexey Nesterov
 */
public class DelegatingAuthorizationGrantAuthenticationConverterTests {
	private Converter<HttpServletRequest, Authentication> clientCredentialsAuthenticationConverter;
	private DelegatingAuthorizationGrantAuthenticationConverter authenticationConverter;

	@Before
	public void setUp() {
		this.clientCredentialsAuthenticationConverter = mock(Converter.class);
		Map<AuthorizationGrantType, Converter<HttpServletRequest, Authentication>> converters =
				Collections.singletonMap(AuthorizationGrantType.CLIENT_CREDENTIALS, this.clientCredentialsAuthenticationConverter);
		this.authenticationConverter = new DelegatingAuthorizationGrantAuthenticationConverter(converters);
	}

	@Test
	public void constructorWhenConvertersEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DelegatingAuthorizationGrantAuthenticationConverter(Collections.emptyMap()))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("converters cannot be empty");
	}

	@Test
	public void convertWhenRequestNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationConverter.convert(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("request cannot be null");
	}

	@Test
	public void convertWhenGrantTypeMissingThenNull() {
		MockHttpServletRequest request = MockMvcRequestBuilders
				.post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.buildRequest(new MockServletContext());

		Authentication authentication = this.authenticationConverter.convert(request);
		assertThat(authentication).isNull();
		verifyNoInteractions(this.clientCredentialsAuthenticationConverter);
	}

	@Test
	public void convertWhenGrantTypeUnsupportedThenNull() {
		MockHttpServletRequest request = MockMvcRequestBuilders
				.post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, "extension_grant_type")
				.buildRequest(new MockServletContext());

		Authentication authentication = this.authenticationConverter.convert(request);
		assertThat(authentication).isNull();
		verifyNoInteractions(this.clientCredentialsAuthenticationConverter);
	}

	@Test
	public void convertWhenGrantTypeSupportedThenConverterCalled() {
		OAuth2ClientCredentialsAuthenticationToken expectedAuthentication =
				new OAuth2ClientCredentialsAuthenticationToken(
						new OAuth2ClientAuthenticationToken(
								TestRegisteredClients.registeredClient().build()));
		when(this.clientCredentialsAuthenticationConverter.convert(any())).thenReturn(expectedAuthentication);

		MockHttpServletRequest request = MockMvcRequestBuilders
				.post(OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.buildRequest(new MockServletContext());

		Authentication authentication = this.authenticationConverter.convert(request);
		assertThat(authentication).isEqualTo(expectedAuthentication);
		verify(this.clientCredentialsAuthenticationConverter).convert(request);
	}
}
