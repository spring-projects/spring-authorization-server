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
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2TokenEndpointFilter}.
 *
 * @author Madhu Bhat
 */
public class OAuth2TokenEndpointFilterTests {

	private OAuth2TokenEndpointFilter filter;
	private OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
	private AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
	private FilterChain filterChain = mock(FilterChain.class);
	private String requestUri;
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final String PRINCIPAL_NAME = "principal";
	private static final String AUTHORIZATION_CODE = "code";

	@Before
	public void setUp() {
		this.filter = new OAuth2TokenEndpointFilter(this.authorizationService, this.authenticationManager);
		this.requestUri = "/oauth2/token";
	}

	@Test
	public void constructorServiceAndManagerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			new OAuth2TokenEndpointFilter(null, null);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorServiceAndManagerAndEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			new OAuth2TokenEndpointFilter(null, null, null);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void doFilterWhenNotTokenRequestThenNextFilter() throws Exception {
		this.requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", this.requestUri);
		request.setServletPath(this.requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verify(this.filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAccessTokenRequestWithoutGrantTypeThenRespondWithBadRequest() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "testAuthCode");
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "testRedirectUri");
		request.setServletPath(this.requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verifyNoInteractions(this.filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getContentAsString()).isEqualTo("{\"errorCode\":\"invalid_request\"}");
	}

	@Test
	public void doFilterWhenAccessTokenRequestWithoutCodeThenRespondWithBadRequest() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.requestUri);
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, "testGrantType");
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "testRedirectUri");
		request.setServletPath(this.requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verifyNoInteractions(this.filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getContentAsString()).isEqualTo("{\"errorCode\":\"invalid_request\"}");
	}

	@Test
	public void doFilterWhenAccessTokenRequestWithoutRedirectUriThenRespondWithBadRequest() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.requestUri);
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, "testGrantType");
		request.addParameter(OAuth2ParameterNames.CODE, "testAuthCode");
		request.setServletPath(this.requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verifyNoInteractions(this.filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getContentAsString()).isEqualTo("{\"errorCode\":\"invalid_request\"}");
	}

	@Test
	public void doFilterWhenAccessTokenRequestWithoutAuthCodeGrantTypeThenRespondWithBadRequest() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.requestUri);
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, "testGrantType");
		request.addParameter(OAuth2ParameterNames.CODE, "testAuthCode");
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "testRedirectUri");
		request.setServletPath(this.requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.filter.doFilter(request, response, this.filterChain);

		verifyNoInteractions(this.filterChain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getContentAsString()).isEqualTo("{\"errorCode\":\"unsupported_grant_type\"}");
	}

	@Test
	public void doFilterWhenAccessTokenRequestIsNotAuthenticatedThenRespondWithUnauthorized() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.requestUri);
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "testAuthCode");
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "testRedirectUri");
		request.setServletPath(this.requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication clientPrincipal = mock(Authentication.class);
		RegisteredClient registeredClient = mock(RegisteredClient.class);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER,  "testToken", Instant.now().minusSeconds(60), Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.CODE, AUTHORIZATION_CODE)
				.build();
		OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationToken =
				new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
		accessTokenAuthenticationToken.setAuthenticated(false);

		when(this.authorizationService.findByTokenAndTokenType(anyString(), any(TokenType.class))).thenReturn(authorization);
		when(this.authenticationManager.authenticate(any(Authentication.class))).thenReturn(accessTokenAuthenticationToken);

		this.filter.doFilter(request, response, this.filterChain);

		verifyNoInteractions(this.filterChain);
		verify(this.authorizationService, times(0)).save(authorization);
		verify(this.authenticationManager, times(1)).authenticate(any(Authentication.class));
		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		assertThat(response.getContentAsString())
				.isEqualTo("{\"errorCode\":\"invalid_client\"}");
	}

	@Test
	public void doFilterWhenValidAccessTokenRequestThenRespondWithAccessToken() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", this.requestUri);
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "testAuthCode");
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "testRedirectUri");
		request.setServletPath(this.requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication clientPrincipal = mock(Authentication.class);
		RegisteredClient registeredClient = mock(RegisteredClient.class);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER,  "testToken", Instant.now().minusSeconds(60), Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.CODE, AUTHORIZATION_CODE)
				.build();
		OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationToken =
				new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
		accessTokenAuthenticationToken.setAuthenticated(true);

		when(this.authorizationService.findByTokenAndTokenType(anyString(), any(TokenType.class))).thenReturn(authorization);
		when(this.authenticationManager.authenticate(any(Authentication.class))).thenReturn(accessTokenAuthenticationToken);

		this.filter.doFilter(request, response, this.filterChain);

		verifyNoInteractions(this.filterChain);
		verify(this.authorizationService, times(1)).save(authorization);
		verify(this.authenticationManager, times(1)).authenticate(any(Authentication.class));
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentAsString()).contains("\"tokenValue\":\"testToken\"");
		assertThat(response.getContentAsString()).contains("\"tokenType\":{\"value\":\"Bearer\"}");
		assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
		assertThat(response.getHeader(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
	}
}
