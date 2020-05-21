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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

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
 * @since 0.0.1
 */
public class OAuth2AuthorizationEndpointFilterTests {
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
	public void doFilterWhenAuthorizationRequestPostThenNotProcessed() throws Exception {
		String requestUri = OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestNotAuthenticatedThenNotProcessed() throws Exception {
		String requestUri = OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.authentication.setAuthenticated(false);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMissingClientIdThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.removeParameter(OAuth2ParameterNames.CLIENT_ID);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[invalid_request] OAuth 2.0 Parameter: client_id");
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleClientIdThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[invalid_request] OAuth 2.0 Parameter: client_id");
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidClientIdThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, "invalid");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[invalid_request] OAuth 2.0 Parameter: client_id");
	}

	@Test
	public void doFilterWhenAuthorizationRequestAndClientNotAuthorizedToRequestCodeThenUnauthorizedClientError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantTypes(Set::clear)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[unauthorized_client] OAuth 2.0 Parameter: client_id");
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidRedirectUriThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "https://invalid-example.com");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[invalid_request] OAuth 2.0 Parameter: redirect_uri");
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleRedirectUriThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "https://example2.com");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[invalid_request] OAuth 2.0 Parameter: redirect_uri");
	}

	@Test
	public void doFilterWhenAuthorizationRequestExcludesRedirectUriAndMultipleRegisteredThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUri("https://example2.com").build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.removeParameter(OAuth2ParameterNames.REDIRECT_URI);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo("[invalid_request] OAuth 2.0 Parameter: redirect_uri");
	}

	@Test
	public void doFilterWhenAuthorizationRequestMissingResponseTypeThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.removeParameter(OAuth2ParameterNames.RESPONSE_TYPE);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).matches("https://example.com\\?" +
				"error=invalid_request&" +
				"error_description=OAuth%202.0%20Parameter:%20response_type&" +
				"error_uri=https://tools.ietf.org/html/rfc6749%23section-4.1.2.1&" +
				"state=state");
	}

	@Test
	public void doFilterWhenAuthorizationRequestMultipleResponseTypeThenInvalidRequestError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).matches("https://example.com\\?" +
				"error=invalid_request&" +
				"error_description=OAuth%202.0%20Parameter:%20response_type&" +
				"error_uri=https://tools.ietf.org/html/rfc6749%23section-4.1.2.1&" +
				"state=state");
	}

	@Test
	public void doFilterWhenAuthorizationRequestInvalidResponseTypeThenUnsupportedResponseTypeError() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId((eq(registeredClient.getClientId()))))
				.thenReturn(registeredClient);

		MockHttpServletRequest request = createAuthorizationRequest(registeredClient);
		request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).matches("https://example.com\\?" +
				"error=unsupported_response_type&" +
				"error_description=OAuth%202.0%20Parameter:%20response_type&" +
				"error_uri=https://tools.ietf.org/html/rfc6749%23section-4.1.2.1&" +
				"state=state");
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
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("http://localhost/oauth2/authorize");
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(registeredClient.getRedirectUris().iterator().next());
		assertThat(authorizationRequest.getScopes()).containsExactlyInAnyOrderElementsOf(registeredClient.getScopes());
		assertThat(authorizationRequest.getState()).isEqualTo("state");
		assertThat(authorizationRequest.getAdditionalParameters()).isEmpty();
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
}
