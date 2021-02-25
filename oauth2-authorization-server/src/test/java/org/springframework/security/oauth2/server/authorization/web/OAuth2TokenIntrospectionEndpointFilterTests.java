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
package org.springframework.security.oauth2.server.authorization.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor.ACTIVE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2.TOKEN;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2.TOKEN_TYPE_HINT;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.assertj.core.api.Condition;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaims;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2TokenIntrospectionClaimsHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Tests for {@link OAuth2TokenIntrospectionEndpointFilter}.
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionEndpointFilterTests {

	private AuthenticationManager authenticationManager;
	private OAuth2TokenIntrospectionEndpointFilter filter;
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();
	private final HttpMessageConverter<OAuth2TokenIntrospectionClaims> tokenIntrospectionHttpResponseConverter = new OAuth2TokenIntrospectionClaimsHttpMessageConverter();
	private final Condition<Object> scopesMatchesInAnyOrder = new Condition<>(
			scopes -> scopes.equals("scope1 Scope2") || scopes.equals("Scope2 scope1"), "scopes match");
	private final String tokenValue = "token.123";

	@Before
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2TokenIntrospectionEndpointFilter(this.authenticationManager);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionEndpointFilter(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authenticationManager cannot be null");
	}

	@Test
	public void doFilterWhenNotIntrospectionRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenIntrospectionRequestGetThenNotProcessed() throws Exception {
		String requestUri = OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenIntrospectionRequestMissingTokenParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		request.removeParameter(TOKEN);

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(
				TOKEN, OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleTokenParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		request.addParameter(TOKEN, "token.456");

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(
				TOKEN, OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleTokenTypeHintParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		request.addParameter(TOKEN_TYPE_HINT, OAuth2TokenType.REFRESH_TOKEN.getValue());

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(
				TOKEN_TYPE_HINT, OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenIntrospectWithNullClaimsThenNotActiveTokenOkReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		Authentication clientPrincipal = setupSecurityContext();

		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = new OAuth2TokenIntrospectionAuthenticationToken(
				clientPrincipal, null);

		when(this.authenticationManager.authenticate(any())).thenReturn(tokenIntrospectionAuthentication);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertNotActiveTokenResponse(response);
	}

	@Test
	public void doFilterWhenIntrospectWithClaimsThenActiveTokenReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		Authentication clientPrincipal = setupSecurityContext();

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		String clientId = "clientId";
		Map<String, Object> tokenIntrospectionClaims = new HashMap<>();
		tokenIntrospectionClaims.put(ACTIVE, true);
		tokenIntrospectionClaims.put(CLIENT_ID, clientId);
		tokenIntrospectionClaims.put(IAT, issuedAt);
		tokenIntrospectionClaims.put(EXP, expiresAt);
		tokenIntrospectionClaims.put(TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER);
		tokenIntrospectionClaims.put(SCOPE, "scope1 Scope2");

		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = new OAuth2TokenIntrospectionAuthenticationToken(
				clientPrincipal, tokenIntrospectionClaims);

		when(this.authenticationManager.authenticate(any())).thenReturn(tokenIntrospectionAuthentication);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2TokenIntrospectionClaims tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		Map<String, Object> responseMap = tokenIntrospectionResponse.getClaims();
		// @formatter:off
		assertThat(responseMap).contains(
				entry(ACTIVE, true),
				entry(CLIENT_ID, clientId),
				entry(TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue()),
				entry(EXP, expiresAt.getEpochSecond()),
				entry(IAT, issuedAt.getEpochSecond()))
		.hasEntrySatisfying(SCOPE, scopesMatchesInAnyOrder)
		.hasSize(6);
		// @formatter: on
	}

	private void assertNotActiveTokenResponse(MockHttpServletResponse response) throws Exception {
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2TokenIntrospectionClaims tokenIntrospectionResponse = readTokenIntrospectionResponse(response);
		assertThat(tokenIntrospectionResponse.getClaims()).containsEntry("active", false).hasSize(1);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private OAuth2TokenIntrospectionClaims readTokenIntrospectionResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.tokenIntrospectionHttpResponseConverter.read(OAuth2TokenIntrospectionClaims.class, httpResponse);
	}

	private void doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(String parameterName, String errorCode,
			MockHttpServletRequest request) throws Exception {

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		setupSecurityContext();

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
		assertThat(error.getDescription()).isEqualTo("OAuth 2.0 Token Introspection Parameter: " + parameterName);
	}

	private static Authentication setupSecurityContext() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);
		return clientPrincipal;
	}

	private static MockHttpServletRequest createTokenIntrospectionRequest(String token, String tokenTypeHint) {
		String requestUri = OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);

		request.addParameter(TOKEN, token);
		request.addParameter(TOKEN_TYPE_HINT, tokenTypeHint);
		return request;

}
}
