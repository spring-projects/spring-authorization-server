/*
 * Copyright 2023 the original author or authors.
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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationCodeRequestAuthenticationConverter}.
 * 
 * @author Martin Lindström
 */
public class OAuth2AuthorizationCodeRequestAuthenticationConverterTest {

  private static final String AUTHORIZATION_URI = "/oauth2/authorize";
  private static final String CLIENT_ID = "client-1";
  private static final String REDIRECT_URI = "https://client.example.com/callback";

  private OAuth2AuthorizationCodeRequestAuthenticationConverter converter;

  @BeforeEach
  public void setUp() {
      this.converter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
  }

  @AfterEach
  public void tearDown() {
      SecurityContextHolder.clearContext();
  }
  
  @Test
  public void convertWhenUnknownParametersHaveMultipleValuesThenReturnOAuth2AuthorizationCodeRequestAuthenticationToken() {
      MockHttpServletRequest request = createRequest();
      request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
      request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
      request.addParameter(OAuth2ParameterNames.REDIRECT_URI, REDIRECT_URI);
      request.addParameter(OAuth2ParameterNames.SCOPE, "message.read message.write");
      request.addParameter(OAuth2ParameterNames.STATE, "qwerty123");
      request.addParameter("foo", "foo-value");
      request.addParameter("bar", "value1", "value2");
      
      OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
	      (OAuth2AuthorizationCodeRequestAuthenticationToken) this.converter.convert(request);
      assertThat(authentication).isNotNull();
      assertThat(authentication.getPrincipal()).isNotNull();
      assertThat(authentication.getAuthorizationUri()).endsWith(AUTHORIZATION_URI);
      assertThat(authentication.getClientId()).isEqualTo(CLIENT_ID);
      assertThat(authentication.getRedirectUri()).isEqualTo(REDIRECT_URI);
      assertThat(authentication.getScopes()).containsExactly("message.read", "message.write");
      assertThat(authentication.getState()).isEqualTo("qwerty123");
      assertThat(authentication.getAdditionalParameters()).hasSize(2);
      assertThat(authentication.getAdditionalParameters().get("foo")).isEqualTo("foo-value");
      assertThat(authentication.getAdditionalParameters().get("bar")).isInstanceOf(String[].class);
      assertThat((String[]) authentication.getAdditionalParameters().get("bar")).containsExactly("value1", "value2");
  }

  private static MockHttpServletRequest createRequest() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.setMethod(HttpMethod.GET.name());
      request.setRequestURI(AUTHORIZATION_URI);
      return request;
  }
  
}
