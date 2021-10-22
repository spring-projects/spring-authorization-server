/*
 * Copyright 2020-2021 the original author or authors.
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

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link JwtClientAssertionAuthenticationConverter}
 *
 * @author Rafal Lewczuk
 */
public class JwtClientAssertionAuthenticationConverterTests {

	private JwtClientAssertionAuthenticationConverter converter = new JwtClientAssertionAuthenticationConverter();

	private static final String JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private void shouldThrow(MockHttpServletRequest request, String errorCode) {
		assertThatThrownBy(() -> this.converter.convert(request))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(errorCode);
	}

	@Test
	public void convertWhenClientAssertionTypeNullThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "some_jwt_assertion");
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMissingClientAssertionThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMissingClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "some_jwt_assertion");
		shouldThrow(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenMultipleClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "some_client");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "other_client");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "some_jwt_assertion");
		shouldThrow(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenBadAssertionTypeThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "some_client");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, "borken");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "some_jwt_assertion");
		shouldThrow(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenMissingClientJwtAssertionTypeThenDoNotProcessClientIdAndReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "some_client");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "throw_something_when_client_id_is_processed");
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMultipleAssertionsThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "some_client");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "some_jwt_assertion");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "other_jwt_assertion");
		shouldThrow(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenValidAssertionJwt() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "some_client");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "some_jwt_assertion");
		request.setRequestURI("/oauth2/token");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getRequestUri()).isEqualTo("/oauth2/token");
		assertThat(authentication.getPrincipal()).isEqualTo("some_client");
		assertThat(authentication.getCredentials()).isEqualTo("some_jwt_assertion");
	}

	@Test
	public void convertWhenConfidentialClientWithPkceParametersThenAdditionalParametersIncluded() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(PkceParameterNames.CODE_VERIFIER, "code-verifier-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "some_client");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "some_jwt_assertion");
		request.setRequestURI("/oauth2/token");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getRequestUri()).isEqualTo("/oauth2/token");
		assertThat(authentication.getPrincipal()).isEqualTo("some_client");
		assertThat(authentication.getCredentials()).isEqualTo("some_jwt_assertion");
		assertThat(authentication.getAdditionalParameters())
				.containsOnly(
						entry(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
						entry(OAuth2ParameterNames.CODE, "code"),
						entry(PkceParameterNames.CODE_VERIFIER, "code-verifier-1"));
	}
}
