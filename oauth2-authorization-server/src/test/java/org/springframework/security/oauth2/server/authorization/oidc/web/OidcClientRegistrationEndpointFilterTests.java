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
package org.springframework.security.oauth2.server.authorization.oidc.web;

import java.time.Instant;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.TestJoseHeaders;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OidcClientRegistrationEndpointFilter}.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 */
public class OidcClientRegistrationEndpointFilterTests {
	private static final String DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI = "/connect/register";
	private AuthenticationManager authenticationManager;
	private OidcClientRegistrationEndpointFilter filter;
	private final HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter =
			new OidcClientRegistrationHttpMessageConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();

	@Before
	public void setup() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OidcClientRegistrationEndpointFilter(this.authenticationManager);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcClientRegistrationEndpointFilter(null))
				.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenClientRegistrationEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcClientRegistrationEndpointFilter(this.authenticationManager, null))
				.withMessage("clientRegistrationEndpointUri cannot be empty");
	}

	@Test
	public void doFilterWhenNotClientRegistrationRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenClientRegistrationRequestGetThenNotProcessed() throws Exception {
		String requestUri = DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenClientRegistrationRequestInvalidThenInvalidRequestError() throws Exception {
		String requestUri = DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setContent("invalid content".getBytes());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		assertThat(error.getDescription()).startsWith("OpenID Client Registration Error: ");
	}

	@Test
	public void doFilterWhenClientRegistrationRequestInvalidTokenThenUnauthorizedError() throws Exception {
		doFilterWhenClientRegistrationRequestInvalidThenError(
				OAuth2ErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void doFilterWhenClientRegistrationRequestInsufficientTokenScopeThenForbiddenError() throws Exception {
		doFilterWhenClientRegistrationRequestInvalidThenError(
				OAuth2ErrorCodes.INSUFFICIENT_SCOPE, HttpStatus.FORBIDDEN);
	}

	private void doFilterWhenClientRegistrationRequestInvalidThenError(
			String errorCode, HttpStatus status) throws Exception {
		Jwt jwt = createJwt();
		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create"));

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(principal);
		SecurityContextHolder.setContext(securityContext);

		when(this.authenticationManager.authenticate(any()))
				.thenThrow(new OAuth2AuthenticationException(new OAuth2Error(errorCode)));

		// @formatter:off
		OidcClientRegistration clientRegistrationRequest = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		String requestUri = DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		writeClientRegistrationRequest(request, clientRegistrationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(status.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
	}

	@Test
	public void doFilterWhenClientRegistrationRequestValidThenSuccessResponse() throws Exception {
		// @formatter:off
		OidcClientRegistration.Builder clientRegistrationBuilder = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2");

		OidcClientRegistration clientRegistrationRequest = clientRegistrationBuilder.build();

		OidcClientRegistration expectedClientRegistrationResponse = clientRegistrationBuilder
				.clientId("client-id")
				.clientIdIssuedAt(Instant.now())
				.clientSecret("client-secret")
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue())
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.idTokenSignedResponseAlgorithm(SignatureAlgorithm.RS256.getName())
				.build();
		// @formatter:on

		Jwt jwt = createJwt();
		JwtAuthenticationToken principal = new JwtAuthenticationToken(
				jwt, AuthorityUtils.createAuthorityList("SCOPE_client.create"));

		OidcClientRegistrationAuthenticationToken clientRegistrationAuthenticationResult =
				new OidcClientRegistrationAuthenticationToken(principal, expectedClientRegistrationResponse);

		when(this.authenticationManager.authenticate(any())).thenReturn(clientRegistrationAuthenticationResult);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(principal);
		SecurityContextHolder.setContext(securityContext);

		String requestUri = DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		writeClientRegistrationRequest(request, clientRegistrationRequest);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.CREATED.value());
		OidcClientRegistration clientRegistrationResponse = readClientRegistrationResponse(response);
		assertThat(clientRegistrationResponse.getClientId()).isEqualTo(expectedClientRegistrationResponse.getClientId());
		assertThat(clientRegistrationResponse.getClientIdIssuedAt()).isBetween(
				expectedClientRegistrationResponse.getClientIdIssuedAt().minusSeconds(1),
				expectedClientRegistrationResponse.getClientIdIssuedAt().plusSeconds(1));
		assertThat(clientRegistrationResponse.getClientSecret()).isEqualTo(expectedClientRegistrationResponse.getClientSecret());
		assertThat(clientRegistrationResponse.getClientSecretExpiresAt()).isEqualTo(expectedClientRegistrationResponse.getClientSecretExpiresAt());
		assertThat(clientRegistrationResponse.getClientName()).isEqualTo(expectedClientRegistrationResponse.getClientName());
		assertThat(clientRegistrationResponse.getRedirectUris())
				.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getRedirectUris());
		assertThat(clientRegistrationResponse.getGrantTypes())
				.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getGrantTypes());
		assertThat(clientRegistrationResponse.getResponseTypes())
				.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getResponseTypes());
		assertThat(clientRegistrationResponse.getScopes())
				.containsExactlyInAnyOrderElementsOf(expectedClientRegistrationResponse.getScopes());
		assertThat(clientRegistrationResponse.getTokenEndpointAuthenticationMethod())
				.isEqualTo(expectedClientRegistrationResponse.getTokenEndpointAuthenticationMethod());
		assertThat(clientRegistrationResponse.getIdTokenSignedResponseAlgorithm())
				.isEqualTo(expectedClientRegistrationResponse.getIdTokenSignedResponseAlgorithm());
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private void writeClientRegistrationRequest(MockHttpServletRequest request,
			OidcClientRegistration clientRegistration) throws Exception {
		MockClientHttpRequest httpRequest = new MockClientHttpRequest();
		this.clientRegistrationHttpMessageConverter.write(clientRegistration, null, httpRequest);
		request.setContent(httpRequest.getBodyAsBytes());
	}

	private OidcClientRegistration readClientRegistrationResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return this.clientRegistrationHttpMessageConverter.read(OidcClientRegistration.class, httpResponse);
	}

	private static Jwt createJwt() {
		// @formatter:off
		JoseHeader joseHeader = TestJoseHeaders.joseHeader()
				.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet()
				.claim(OAuth2ParameterNames.SCOPE, Collections.singleton("client.create"))
				.build();
		Jwt jwt = Jwt.withTokenValue("jwt-access-token")
				.headers(headers -> headers.putAll(joseHeader.getHeaders()))
				.claims(claims -> claims.putAll(jwtClaimsSet.getClaims()))
				.build();
		// @formatter:on
		return jwt;
	}

}
