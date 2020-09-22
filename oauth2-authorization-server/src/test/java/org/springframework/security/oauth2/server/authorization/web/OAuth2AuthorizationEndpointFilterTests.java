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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
 * @since 0.0.1
 */
public class OAuth2AuthorizationEndpointFilterTests {
	private static final String DEFAULT_ERROR_URI = "https://tools.ietf.org/html/rfc6749%23section-4.1.2.1";
	private static final String PKCE_ERROR_URI = "https://tools.ietf.org/html/rfc7636%23section-4.4.1";
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2AuthorizationService authorizationService;
	private OAuth2AuthorizationEndpointFilter filter;
	private TestingAuthenticationToken authentication;

	@Before
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.filter = new OAuth2AuthorizationEndpointFilter(this.registeredClientRepository, this.authorizationService);
		this.authentication = new TestingAuthenticationToken("principalName", "password");
		this.authentication.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(this.authentication);
		SecurityContextHolder.setContext(securityContext);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationEndpointFilter(null, this.authorizationService))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationEndpointFilter(this.registeredClientRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationEndpointFilter(this.registeredClientRepository, this.authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationEndpointUri cannot be empty");
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
	public void doFilterWhenAuthorizationRequestInvalidClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.setParameter(OAuth2ParameterNames.CLIENT_ID, "invalid"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestAndClientNotAuthorizedToRequestCodeThenUnauthorizedClientError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantTypes(Set::clear)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidRedirectUriThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.REDIRECT_URI,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "https://invalid-example.com"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleRedirectUriThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.REDIRECT_URI,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "https://example2.com"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestExcludesRedirectUriAndMultipleRegisteredThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUri("https://example2.com").build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.REDIRECT_URI,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.removeParameter(OAuth2ParameterNames.REDIRECT_URI));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMissingResponseTypeThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				DEFAULT_ERROR_URI,
				request -> request.removeParameter(OAuth2ParameterNames.RESPONSE_TYPE));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleResponseTypeThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				DEFAULT_ERROR_URI,
				request -> request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidResponseTypeThenUnsupportedResponseTypeError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
				DEFAULT_ERROR_URI,
				request -> request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token"));
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidScopeThenInvalidScopeError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				OAuth2ParameterNames.SCOPE,
				OAuth2ErrorCodes.INVALID_SCOPE,
				DEFAULT_ERROR_URI,
				request -> {
					String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
					request.setParameter(OAuth2ParameterNames.SCOPE, scope + " invalid-scope");
				});
	}

	@Test
	public void doFilterWhenPkceRequiredAndMissingCodeChallengeThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(new ClientSettings().requireProofKey(true))
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				PkceParameterNames.CODE_CHALLENGE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				PKCE_ERROR_URI,
				request -> {
					addPkceParameters(request);
					request.removeParameter(PkceParameterNames.CODE_CHALLENGE);
				});
	}

	@Test
	public void doFilterWhenPkceRequiredAndMultipleCodeChallengeThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(new ClientSettings().requireProofKey(true))
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				PkceParameterNames.CODE_CHALLENGE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				PKCE_ERROR_URI,
				request -> {
					addPkceParameters(request);
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "another-code-challenge");
				});
	}

	@Test
	public void doFilterWhenPkceNotRequiredAndMultipleCodeChallengeThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				PkceParameterNames.CODE_CHALLENGE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				PKCE_ERROR_URI,
				request -> {
					addPkceParameters(request);
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "another-code-challenge");
				});
	}

	@Test
	public void doFilterWhenPkceRequiredAndMultipleCodeChallengeMethodThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(new ClientSettings().requireProofKey(true))
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				PkceParameterNames.CODE_CHALLENGE_METHOD,
				OAuth2ErrorCodes.INVALID_REQUEST,
				PKCE_ERROR_URI,
				request -> {
					addPkceParameters(request);
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "plain");
				});
	}

	@Test
	public void doFilterWhenPkceNotRequiredAndMultipleCodeChallengeMethodThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				PkceParameterNames.CODE_CHALLENGE_METHOD,
				OAuth2ErrorCodes.INVALID_REQUEST,
				PKCE_ERROR_URI,
				request -> {
					addPkceParameters(request);
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "plain");
				});
	}

	@Test
	public void doFilterWhenPkceRequiredAndUnsupportedCodeChallengeMethodThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(new ClientSettings().requireProofKey(true))
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				PkceParameterNames.CODE_CHALLENGE_METHOD,
				OAuth2ErrorCodes.INVALID_REQUEST,
				PKCE_ERROR_URI,
				request -> {
					addPkceParameters(request);
					request.setParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "unsupported");
				});
	}

	@Test
	public void doFilterWhenPkceNotRequiredAndUnsupportedCodeChallengeMethodThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(
				registeredClient,
				PkceParameterNames.CODE_CHALLENGE_METHOD,
				OAuth2ErrorCodes.INVALID_REQUEST,
				PKCE_ERROR_URI,
				request -> {
					addPkceParameters(request);
					request.setParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "unsupported");
				});
	}

	@Test
	public void doFilterWhenAuthorizationRequestValidNotAuthenticatedThenContinueChainToCommenceAuthentication() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.authentication.setAuthenticated(false);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestValidThenAuthorizationResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).matches("https://example.com\\?code=.{15,}&state=state");

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);

		verify(this.authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(this.authentication.getPrincipal().toString());

		String code = authorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE);
		assertThat(code).isNotNull();

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		assertThat(authorizationRequest).isNotNull();

		Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
		assertThat(authorizedScopes).isEqualTo(authorizationRequest.getScopes());

		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("http://localhost/oauth2/authorize");
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(registeredClient.getRedirectUris().iterator().next());
		assertThat(authorizationRequest.getScopes()).containsExactlyInAnyOrderElementsOf(registeredClient.getScopes());
		assertThat(authorizationRequest.getState()).isEqualTo("state");
		assertThat(authorizationRequest.getAdditionalParameters()).isEmpty();
	}

	@Test
	public void doFilterWhenPkceRequiredAndAuthorizationRequestValidThenAuthorizationResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(new ClientSettings().requireProofKey(true))
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		addPkceParameters(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).matches("https://example.com\\?code=.{15,}&state=state");

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);

		verify(this.authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(this.authentication.getPrincipal().toString());

		String code = authorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE);
		assertThat(code).isNotNull();

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		assertThat(authorizationRequest).isNotNull();

		Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
		assertThat(authorizedScopes).isEqualTo(authorizationRequest.getScopes());

		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authorizationRequest.getAdditionalParameters())
				.size()
				.isEqualTo(2)
				.returnToMap()
				.containsEntry(PkceParameterNames.CODE_CHALLENGE, "code-challenge")
				.containsEntry(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
	}

	@Test
	public void doFilterWhenUserConsentRequiredAndAuthorizationRequestValidThenUserConsentResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(new ClientSettings().requireUserConsent(true))
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType().equals(new MediaType("text", "html", StandardCharsets.UTF_8).toString()));

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);

		verify(this.authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(this.authentication.getPrincipal().toString());

		String state = authorization.getAttribute(OAuth2AuthorizationAttributeNames.STATE);
		assertThat(state).isNotNull();

		Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
		assertThat(authorizedScopes).isNull();

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		assertThat(authorizationRequest).isNotNull();
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("http://localhost/oauth2/authorize");
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(registeredClient.getRedirectUris().iterator().next());
		assertThat(authorizationRequest.getScopes()).containsExactlyInAnyOrderElementsOf(registeredClient.getScopes());
		assertThat(authorizationRequest.getState()).isEqualTo("state");
		assertThat(authorizationRequest.getAdditionalParameters()).isEmpty();
	}

	@Test
	public void doFilterWhenUserConsentRequestMissingStateThenInvalidRequestError() throws Exception {
		doFilterWhenUserConsentRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.removeParameter(OAuth2ParameterNames.STATE));
	}

	@Test
	public void doFilterWhenUserConsentRequestMultipleStateThenInvalidRequestError() throws Exception {
		doFilterWhenUserConsentRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.STATE, "state-2"));
	}

	@Test
	public void doFilterWhenUserConsentRequestInvalidStateThenInvalidRequestError() throws Exception {
		doFilterWhenUserConsentRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.setParameter(OAuth2ParameterNames.STATE, "invalid"));
	}

	@Test
	public void doFilterWhenUserConsentRequestNotAuthenticatedThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		this.authentication.setAuthenticated(false);

		doFilterWhenUserConsentRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> {});
	}

	@Test
	public void doFilterWhenUserConsentRequestInvalidPrincipalThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		this.authentication = new TestingAuthenticationToken("other-principal", "password");
		this.authentication.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(this.authentication);
		SecurityContextHolder.setContext(securityContext);

		doFilterWhenUserConsentRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> {});
	}

	@Test
	public void doFilterWhenUserConsentRequestMissingClientIdThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.authentication.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		doFilterWhenUserConsentRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.removeParameter(OAuth2ParameterNames.CLIENT_ID));
	}

	@Test
	public void doFilterWhenUserConsentRequestMultipleClientIdThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.authentication.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		doFilterWhenUserConsentRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(),
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2"));
	}

	@Test
	public void doFilterWhenUserConsentRequestInvalidClientIdThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.authentication.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		doFilterWhenUserConsentRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> request.setParameter(OAuth2ParameterNames.CLIENT_ID, "invalid"));
	}

	@Test
	public void doFilterWhenUserConsentRequestDoesNotMatchClientThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		RegisteredClient otherRegisteredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(otherRegisteredClient)
				.principalName(this.authentication.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		doFilterWhenUserConsentRequestInvalidParameterThenError(
				registeredClient,
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				request -> {});
	}

	@Test
	public void doFilterWhenUserConsentRequestInvalidScopeThenInvalidScopeError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.authentication.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		doFilterWhenUserConsentRequestInvalidParameterThenRedirect(
				registeredClient,
				OAuth2ParameterNames.SCOPE,
				OAuth2ErrorCodes.INVALID_SCOPE,
				DEFAULT_ERROR_URI,
				request -> {
					request.addParameter(OAuth2ParameterNames.SCOPE, "invalid-scope");
				});
	}

	@Test
	public void doFilterWhenUserConsentRequestNotApprovedThenAccessDeniedError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.authentication.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		doFilterWhenUserConsentRequestInvalidParameterThenRedirect(
				registeredClient,
				OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.ACCESS_DENIED,
				DEFAULT_ERROR_URI,
				request -> request.removeParameter("consent_action"));

		verify(this.authorizationService).remove(eq(authorization));
	}

	@Test
	public void doFilterWhenUserConsentRequestApprovedThenAuthorizationResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.authentication.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(new TokenType(OAuth2AuthorizationAttributeNames.STATE))))
				.thenReturn(authorization);

		MockHttpServletRequest request = createUserConsentRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).matches("https://example.com\\?code=.{15,}&state=state");

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);

		verify(this.authorizationService).save(authorizationCaptor.capture());

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(updatedAuthorization.getPrincipalName()).isEqualTo(this.authentication.getPrincipal().toString());
		assertThat(updatedAuthorization.getAccessToken()).isNotNull();
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2AuthorizationAttributeNames.STATE)).isNull();
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2AuthorizationAttributeNames.CODE)).isNotNull();
		assertThat(updatedAuthorization.<OAuth2AuthorizationRequest>getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST))
				.isEqualTo(authorization.<OAuth2AuthorizationRequest>getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST));
		assertThat(updatedAuthorization.<Set<String>>getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES))
				.isEqualTo(registeredClient.getScopes());
	}

	private void doFilterWhenAuthorizationRequestInvalidParameterThenError(RegisteredClient registeredClient,
			String parameterName, String errorCode) throws Exception {
		doFilterWhenAuthorizationRequestInvalidParameterThenError(registeredClient, parameterName, errorCode, request -> {});
	}

	private void doFilterWhenAuthorizationRequestInvalidParameterThenError(RegisteredClient registeredClient,
			String parameterName, String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenError(createAuthorizationRequest(registeredClient),
				parameterName, errorCode, requestConsumer);
	}

	private void doFilterWhenAuthorizationRequestInvalidParameterThenRedirect(RegisteredClient registeredClient,
			String parameterName, String errorCode, String errorUri,
			Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenRedirect(createAuthorizationRequest(registeredClient),
				parameterName, errorCode, errorUri, requestConsumer);
	}

	private void doFilterWhenUserConsentRequestInvalidParameterThenError(RegisteredClient registeredClient,
			String parameterName, String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenError(createUserConsentRequest(registeredClient),
				parameterName, errorCode, requestConsumer);
	}

	private void doFilterWhenUserConsentRequestInvalidParameterThenRedirect(RegisteredClient registeredClient,
			String parameterName, String errorCode, String errorUri,
			Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenRedirect(createUserConsentRequest(registeredClient),
				parameterName, errorCode, errorUri, requestConsumer);
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

	private void doFilterWhenRequestInvalidParameterThenRedirect(MockHttpServletRequest request,
			String parameterName, String errorCode, String errorUri,
			Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		requestConsumer.accept(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).matches("https://example.com\\?" +
				"error=" + errorCode + "&" +
				"error_description=OAuth%202.0%20Parameter:%20" + parameterName + "&" +
				"error_uri=" + errorUri + "&" +
				"state=state");
	}

	private static MockHttpServletRequest createAuthorizationRequest(RegisteredClient registeredClient) {
		String[] redirectUris = registeredClient.getRedirectUris().toArray(new String[0]);

		String requestUri = OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);

		request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, redirectUris[0]);
		request.addParameter(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		request.addParameter(OAuth2ParameterNames.STATE, "state");

		return request;
	}

	private static void addPkceParameters(MockHttpServletRequest request) {
		request.addParameter(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
		request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
	}

	private static MockHttpServletRequest createUserConsentRequest(RegisteredClient registeredClient) {
		String requestUri = OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);

		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		for (String scope : registeredClient.getScopes()) {
			request.addParameter(OAuth2ParameterNames.SCOPE, scope);
		}
		request.addParameter("consent_action", "approve");

		return request;
	}
}
