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

import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2AuthorizationEndpointFilter}.
 *
 * @author Paurav Munshi
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Anoop Garlapati
 * @since 0.0.1
 */
public class OAuth2AuthorizationEndpointFilterTests {
	private AuthenticationManager authenticationManager;
	private OAuth2AuthorizationEndpointFilter filter;
	private TestingAuthenticationToken principal;
	private OAuth2AuthorizationCode authorizationCode;

	@Before
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2AuthorizationEndpointFilter(this.authenticationManager);
		this.principal = new TestingAuthenticationToken("principalName", "password");
		this.principal.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);
		this.authorizationCode = new OAuth2AuthorizationCode("code", issuedAt, expiresAt);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationEndpointFilter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationEndpointFilter(this.authenticationManager, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationEndpointUri cannot be empty");
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationConverter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationConverter cannot be null");
	}

	@Test
	public void setAuthenticationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationSuccessHandler(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthenticationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationFailureHandler(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationFailureHandler cannot be null");
	}

	@Test
	public void doFilterWhenNotAuthorizationRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMissingResponseTypeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.removeParameter(OAuth2ParameterNames.RESPONSE_TYPE));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleResponseTypeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidResponseTypeThenUnsupportedResponseTypeError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
				request -> request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMissingClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.removeParameter(OAuth2ParameterNames.CLIENT_ID));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleRedirectUriThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.REDIRECT_URI,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "https://example2.com"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleScopeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.SCOPE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.SCOPE, "scope2"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleStateThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.STATE, "state2"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleCodeChallengeThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				PkceParameterNames.CODE_CHALLENGE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> {
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "another-code-challenge");
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleCodeChallengeMethodThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				PkceParameterNames.CODE_CHALLENGE_METHOD,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> {
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "plain");
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestAuthenticationExceptionThenErrorResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();
		OAuth2Error error = new OAuth2Error("errorCode", "errorDescription", "errorUri");
		when(this.authenticationManager.authenticate(any()))
				.thenThrow(new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthentication));

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("https://example.com?error=errorCode&error_description=errorDescription&error_uri=errorUri&state=state");
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();

		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		when(authenticationConverter.convert(any())).thenReturn(authorizationCodeRequestAuthentication);
		this.filter.setAuthenticationConverter(authenticationConverter);

		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthentication);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationConverter).convert(any());
		verify(this.authenticationManager).authenticate(any());
		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenCustomAuthenticationSuccessHandlerThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.authorizationCode(this.authorizationCode)
						.build();
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthenticationResult);

		AuthenticationSuccessHandler authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), same(authorizationCodeRequestAuthenticationResult));
	}

	@Test
	public void doFilterWhenCustomAuthenticationFailureHandlerThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();
		OAuth2Error error = new OAuth2Error("errorCode", "errorDescription", "errorUri");
		OAuth2AuthorizationCodeRequestAuthenticationException authenticationException =
				new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthentication);
		when(this.authenticationManager.authenticate(any()))
				.thenThrow(authenticationException);

		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), same(authenticationException));
	}

	@Test
	public void doFilterWhenAuthorizationRequestPrincipalNotAuthenticatedThenCommenceAuthentication() throws Exception {
		this.principal.setAuthenticated(false);
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();
		authorizationCodeRequestAuthenticationResult.setAuthenticated(false);
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestConsentRequiredWithCustomConsentUriThenRedirectConsentResponse() throws Exception {
		Set<String> requestedScopes = new HashSet<>(Arrays.asList("scope1", "scope2"));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.addAll(requestedScopes);
				})
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.scopes(new HashSet<>())	// No scopes previously approved
						.consentRequired(true)
						.build();
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.setConsentPage("/oauth2/custom-consent");
		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/oauth2/custom-consent?scope=scope1%20scope2&client_id=client-1&state=state");
	}

	@Test
	public void doFilterWhenAuthorizationRequestConsentRequiredThenConsentResponse() throws Exception {
		Set<String> requestedScopes = new HashSet<>(Arrays.asList("scope1", "scope2"));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.addAll(requestedScopes);
				})
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.scopes(new HashSet<>())	// No scopes previously approved
						.consentRequired(true)
						.build();
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType().equals(new MediaType("text", "html", StandardCharsets.UTF_8).toString()));
		for (String requestedScope : requestedScopes) {
			assertThat(response.getContentAsString()).contains(scopeCheckbox(requestedScope));
		}
	}

	@Test
	public void doFilterWhenAuthorizationRequestConsentRequiredWithPreviouslyApprovedThenConsentResponse() throws Exception {
		Set<String> approvedScopes = new HashSet<>(Arrays.asList("scope1", "scope2"));
		Set<String> requestedScopes = new HashSet<>(Arrays.asList("scope3", "scope4"));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.addAll(approvedScopes);
					scopes.addAll(requestedScopes);
				})
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.scopes(approvedScopes)
						.consentRequired(true)
						.build();
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType().equals(new MediaType("text", "html", StandardCharsets.UTF_8).toString()));
		for (String requestedScope : requestedScopes) {
			assertThat(response.getContentAsString()).contains(scopeCheckbox(requestedScope));
		}
		for (String approvedScope : approvedScopes) {
			assertThat(response.getContentAsString()).contains(disabledScopeCheckbox(approvedScope));
		}
	}

	@Test
	public void doFilterWhenAuthorizationRequestAuthenticatedThenAuthorizationResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.authorizationCode(this.authorizationCode)
						.build();
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("https://example.com?code=code&state=state");
	}

	@Test
	public void doFilterWhenAuthenticationRequestAuthenticatedThenAuthorizationResponse() throws Exception {
		// Setup OpenID Connect request
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add(OidcScopes.OPENID);
				})
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.authorizationCode(this.authorizationCode)
						.build();
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);
		when(this.authenticationManager.authenticate(any()))
				.thenReturn(authorizationCodeRequestAuthenticationResult);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.setMethod("POST");	// OpenID Connect supports POST method
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("https://example.com?code=code&state=state");
	}

	private void doFilterWhenAuthorizationRequestInvalidParameterThenError(RegisteredClient registeredClient,
			String parameterName, String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenError(createAuthorizationRequest(registeredClient),
				parameterName, errorCode, requestConsumer);
	}

	private void doFilterWhenRequestInvalidParameterThenError(MockHttpServletRequest request,
			String parameterName, String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		requestConsumer.accept(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[" + errorCode + "] OAuth 2.0 Parameter: " + parameterName);
	}

	private static MockHttpServletRequest createAuthorizationRequest(RegisteredClient registeredClient) {
		String requestUri = OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);

		request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		request.addParameter(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		request.addParameter(OAuth2ParameterNames.STATE, "state");

		return request;
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken.Builder authorizationCodeRequestAuthentication(
			RegisteredClient registeredClient, Authentication principal) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri("https://provider.com/oauth2/authorize")
				.redirectUri(registeredClient.getRedirectUris().iterator().next())
				.scopes(registeredClient.getScopes())
				.state("state");
	}

	private static String scopeCheckbox(String scope) {
		return MessageFormat.format(
				"<input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"{0}\" id=\"{0}\">",
				scope
		);
	}

	private static String disabledScopeCheckbox(String scope) {
		return MessageFormat.format(
				"<input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" id=\"{0}\" checked disabled>",
				scope
		);
	}

}
