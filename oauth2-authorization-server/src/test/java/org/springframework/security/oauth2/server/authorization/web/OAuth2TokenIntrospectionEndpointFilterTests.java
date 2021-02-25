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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

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
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.core.endpoint.OAuth2TokenIntrospectionResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.introspection.http.converter.OAuth2TokenIntrospectionResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
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
	private final HttpMessageConverter<OAuth2TokenIntrospectionResponse> tokenIntrospectionHttpResponseConverter = new OAuth2TokenIntrospectionResponseHttpMessageConverter();
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
		request.removeParameter(OAuth2ParameterNames2.TOKEN);

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(
				OAuth2ParameterNames2.TOKEN, OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleTokenParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		request.addParameter(OAuth2ParameterNames2.TOKEN, "token.456");

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(
				OAuth2ParameterNames2.TOKEN, OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleTokenTypeHintParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		request.addParameter(OAuth2ParameterNames2.TOKEN_TYPE_HINT, OAuth2TokenType.REFRESH_TOKEN.getValue());

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(
				OAuth2ParameterNames2.TOKEN_TYPE_HINT, OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenIntrospectWithNullTokenThenNotActiveTokenOkReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		Authentication clientPrincipal = setupSecurityContext();

		String clientId = "clientId";
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = new OAuth2TokenIntrospectionAuthenticationToken(
				clientPrincipal, clientId, null);

		when(this.authenticationManager.authenticate(any())).thenReturn(tokenIntrospectionAuthentication);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertNotActiveTokenResponse(response);
	}

	@Test
	public void doFilterWhenIntrospectAccessTokenThenActiveTokenReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(
				this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		Authentication clientPrincipal = setupSecurityContext();

		String clientId = "clientId";
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "token", issuedAt, expiresAt,
				new HashSet<>(Arrays.asList("scope1", "Scope2")));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().token(accessToken).build();
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = new OAuth2TokenIntrospectionAuthenticationToken(
				clientPrincipal, clientId, authorization.getAccessToken());

		when(this.authenticationManager.authenticate(any())).thenReturn(tokenIntrospectionAuthentication);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2TokenIntrospectionResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		Map<String, Object> responseMap = tokenIntrospectionResponse.getParameters();
		// @formatter:off
		assertThat(responseMap).contains(
				entry("active", true),
				entry("client_id", clientId),
				entry(OAuth2ParameterNames2.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue()),
				entry(JwtClaimNames.EXP, expiresAt.truncatedTo(ChronoUnit.SECONDS)),
				entry(JwtClaimNames.IAT, issuedAt.truncatedTo(ChronoUnit.SECONDS)))
		.hasEntrySatisfying(OAuth2ParameterNames2.SCOPE, scopesMatchesInAnyOrder)
		.hasSize(6);
		// @formatter: on
	}

	@Test
	public void doFilterWhenIntrospectRefreshTokenThenActiveTokenReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest(this.tokenValue, OAuth2TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		Authentication clientPrincipal = setupSecurityContext();

		String clientId = "clientId";
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken2(this.tokenValue, issuedAt,
				expiresAt);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().token(refreshToken).build();
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = new OAuth2TokenIntrospectionAuthenticationToken(
				clientPrincipal, clientId, authorization.getRefreshToken());

		when(this.authenticationManager.authenticate(any())).thenReturn(tokenIntrospectionAuthentication);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2TokenIntrospectionResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		Map<String, Object> responseMap = tokenIntrospectionResponse.getParameters();
		// @formatter:off
		assertThat(responseMap).containsOnly(
				entry("active", true),
				entry("client_id", clientId),
				entry(JwtClaimNames.EXP, expiresAt.truncatedTo(ChronoUnit.SECONDS)),
				entry(JwtClaimNames.IAT, issuedAt.truncatedTo(ChronoUnit.SECONDS)));
		// @formatter: on
	}

	private void assertNotActiveTokenResponse(MockHttpServletResponse response) throws Exception {
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2TokenIntrospectionResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);
		assertThat(tokenIntrospectionResponse.getParameters()).containsEntry("active", false).hasSize(1);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private OAuth2TokenIntrospectionResponse readTokenIntrospectionResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.tokenIntrospectionHttpResponseConverter.read(OAuth2TokenIntrospectionResponse.class, httpResponse);
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

		request.addParameter(OAuth2ParameterNames2.TOKEN, token);
		request.addParameter(OAuth2ParameterNames2.TOKEN_TYPE_HINT, tokenTypeHint);
		return request;

}
}
