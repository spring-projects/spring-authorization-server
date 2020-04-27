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
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import java.util.Base64;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DefaultOAuth2ClientAuthenticationConverter}.
 *
 * @author Patryk Kostrzewa
 */
public class DefaultOAuth2ClientAuthenticationConverterTests {

	private DefaultOAuth2ClientAuthenticationConverter converter;

	@Before
	public void setup() {
		this.converter = new DefaultOAuth2ClientAuthenticationConverter();
	}

	@Test
	public void convertWhenConversionSuccessThenReturnClientAuthenticationToken() {
		String token = "client:secret";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder()
				.encodeToString(token.getBytes()));

		OAuth2ClientAuthenticationToken authentication = this.converter.convert(request);

		assertThat(authentication).isNotNull();
		assertThat(authentication.getName()).isEqualTo("client");
	}

	@Test
	public void convertWithAuthorizationSchemeInMixedCaseWhenConversionSuccessThenReturnClientAuthenticationToken() {
		String token = "client:secret";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "BaSiC " + Base64.getEncoder()
				.encodeToString(token.getBytes()));

		final OAuth2ClientAuthenticationToken authentication = this.converter.convert(request);

		assertThat(authentication).isNotNull();
		assertThat(authentication.getName()).isEqualTo("client");
	}

	@Test
	public void convertWithIgnoringUnsupportedAuthenticationHeaderWhenConversionSuccessThenReturnClientAuthenticationToken() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer unsupportedToken");

		OAuth2ClientAuthenticationToken authentication = this.converter.convert(request);

		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenNotValidTokenThenThrowOAuth2AuthenticationException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder()
				.encodeToString("client".getBytes()));
		assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void convertWhenNotValidBase64ThenThrowOAuth2AuthenticationException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic NOT_VALID_BASE64");
		assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void convertWhenEmptyAuthenticationHeaderTokenThenThrowOAuth2AuthenticationException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic ");
		assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class);
	}
}
