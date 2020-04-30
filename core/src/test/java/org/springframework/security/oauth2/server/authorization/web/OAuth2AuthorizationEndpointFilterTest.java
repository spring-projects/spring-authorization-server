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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;


/**
 * Tests for {@link OAuth2AuthorizationEndpointFilter}.
 *
 * @author Paurav Munshi
 * @since 0.0.1
 */

public class OAuth2AuthorizationEndpointFilterTest {

	private static final String VALID_CLIENT = "valid_client";
	private static final String VALID_CLIENT_MULTI_URI = "valid_client_multi_uri";
	private static final String VALID_CC_CLIENT = "valid_cc_client";

	private OAuth2AuthorizationEndpointFilter filter;

	private OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
	private StringKeyGenerator codeGenerator = mock(StringKeyGenerator.class);
	private RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
	private Authentication authentication = mock(Authentication.class);

	@Before
	public void setUp() {
		this.filter = new OAuth2AuthorizationEndpointFilter(this.registeredClientRepository, this.authorizationService);
		this.filter.setCodeGenerator(this.codeGenerator);

		SecurityContextHolder.getContext().setAuthentication(this.authentication);
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryIsNullThenIllegalArgumentExceptionIsThrows() throws Exception {
		assertThatThrownBy(() -> new OAuth2AuthorizationEndpointFilter(null, this.authorizationService))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAuthorizationServiceIsNullThenIllegalArgumentExceptionIsThrows() throws Exception {
		assertThatThrownBy(() -> new OAuth2AuthorizationEndpointFilter(this.registeredClientRepository, null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setAuthorizationEndpointMatcherWhenAuthorizationEndpointMatcherIsNullThenIllegalArgumentExceptionIsThrown() throws Exception {
		assertThatThrownBy(() ->this.filter.setAuthorizationEndpointMatcher(null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setAuthorizationRedirectStrategyWhenAuthorizationRedirectStrategyIsNullThenIllegalArgumentExceptionIsThrown() throws Exception {
		assertThatThrownBy(() ->this.filter.setAuthorizationRedirectStrategy(null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setAuthorizationRequestConverterWhenAuthorizationRequestConverterIsNullThenIllegalArgumentExceptionIsThrown() throws Exception {
		assertThatThrownBy(() ->this.filter.setAuthorizationRequestConverter(null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setCodeGeneratorWhenCodeGeneratorIsNullThenIllegalArgumentExceptionIsThrown() throws Exception {
		assertThatThrownBy(() ->this.filter.setCodeGenerator(null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void doFilterWhenValidRequestIsReceivedThenResponseRedirectedToRedirectURIWithCode() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(this.registeredClientRepository.findByClientId(VALID_CLIENT)).thenReturn(registeredClient);
		when(this.codeGenerator.generateKey()).thenReturn("sample_code");
		when(this.authentication.getPrincipal()).thenReturn("test-user");
		when(this.authentication.isAuthenticated()).thenReturn(true);


		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication).isAuthenticated();
		verify(this.registeredClientRepository).findByClientId(VALID_CLIENT);
		verify(this.authorizationService).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:8080/test-application/callback?code=sample_code&state=teststate");

	}

	@Test
	public void doFilterWhenValidRequestWithBlankRedirectURIIsReceivedThenResponseRedirectedToConfiguredRedirectURI() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(this.registeredClientRepository.findByClientId(VALID_CLIENT)).thenReturn(registeredClient);
		when(this.codeGenerator.generateKey()).thenReturn("sample_code");
		when(this.authentication.getPrincipal()).thenReturn("test-user");
		when(this.authentication.isAuthenticated()).thenReturn(true);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication).isAuthenticated();
		verify(this.registeredClientRepository).findByClientId(VALID_CLIENT);
		verify(this.authorizationService).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:8080/test-application/callback?code=sample_code&state=teststate");

	}

	@Test
	public void doFilterWhenRedirectURINotPresentAndClientHasMulitipleUrisThenErrorIsSentInResponse() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, VALID_CLIENT_MULTI_URI);
		request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantClientMultiRedirectUris().build();
		when(this.registeredClientRepository.findByClientId(VALID_CLIENT_MULTI_URI)).thenReturn(registeredClient);
		when(this.authentication.isAuthenticated()).thenReturn(true);


		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication, times(1)).isAuthenticated();
		verify(this.registeredClientRepository, times(1)).findByClientId(VALID_CLIENT_MULTI_URI);
		verify(this.authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator, times(0)).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);

	}

	@Test
	public void doFilterWhenRequestedRedirectUriNotConfiguredInClientThenErrorSentInResponse() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "http://localhost:8080/not-configred-app/callback");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(this.registeredClientRepository.findByClientId(VALID_CLIENT)).thenReturn(registeredClient);
		when(this.authentication.isAuthenticated()).thenReturn(true);


		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication, times(1)).isAuthenticated();
		verify(this.registeredClientRepository, times(1)).findByClientId(VALID_CLIENT);
		verify(this.authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator, times(0)).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);

	}

	@Test
	public void doFilterWhenClientIdDoesNotSupportAuthorizationGrantFlowThenErrorSentInResponse() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, VALID_CC_CLIENT);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validClientCredentialsGrantRegisteredClient().build();
		when(this.registeredClientRepository.findByClientId(VALID_CC_CLIENT)).thenReturn(registeredClient);
		when(this.authentication.isAuthenticated()).thenReturn(true);


		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication, times(1)).isAuthenticated();
		verify(this.registeredClientRepository, times(1)).findByClientId(VALID_CC_CLIENT);
		verify(this.authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator, times(0)).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED);

	}

	@Test
	public void doFilterWhenClientIdIsMissinInRequestThenErrorSentInResponse() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		when(this.authentication.isAuthenticated()).thenReturn(true);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication).isAuthenticated();
		verify(this.registeredClientRepository, times(0)).findByClientId(anyString());
		verify(this.authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator, times(0)).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
		assertThat(response.getContentAsString()).isEmpty();
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);

	}

	@Test
	public void doFilterWhenUnregisteredClientInRequestThenErrorIsSentInResponse() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, "unregistered_client");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		when(this.registeredClientRepository.findByClientId("unregistered_client")).thenReturn(null);
		when(this.codeGenerator.generateKey()).thenReturn("sample_code");
		when(this.authentication.isAuthenticated()).thenReturn(true);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication).isAuthenticated();
		verify(this.registeredClientRepository, times(1)).findByClientId("unregistered_client");
		verify(this.authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator, times(0)).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
		assertThat(response.getContentAsString()).isEmpty();
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED);

	}

	@Test
	public void doFilterWhenUnauthenticatedUserInRequestThenErrorIsSentInResponse() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		when(authentication.isAuthenticated()).thenReturn(false);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authentication).isAuthenticated();
		verify(this.registeredClientRepository, times(0)).findByClientId(anyString());
		verify(this.authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(this.codeGenerator, times(0)).generateKey();
		verify(filterChain, times(0)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
		assertThat(response.getContentAsString()).isEmpty();
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED);

	}

	@Test
	public void doFilterWhenRequestEndPointIsNotAuthorizationEndpointThenFilterShouldProceedWithFilterChain() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setServletPath("/custom/authorize");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		OAuth2AuthorizationEndpointFilter spyFilter = spy(this.filter);
		spyFilter.doFilter(request, response, filterChain);

		verify(filterChain, times(1)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(spyFilter, times(1)).shouldNotFilter(any(HttpServletRequest.class));
		verify(spyFilter, times(0)).doFilterInternal(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
	}

	@Test
	public void doFilterWhenResponseTypeIsNotPresentInRequestThenErrorIsSentInRedirectURIQueryParameter() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		OAuth2AuthorizationEndpointFilter spyFilter = spy(this.filter);
		spyFilter.doFilter(request, response, filterChain);

		verify(spyFilter, times(1)).shouldNotFilter(any(HttpServletRequest.class));
		verify(spyFilter, times(0)).doFilterInternal(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
		verify(filterChain, times(1)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenResponseTypeInRequestIsUnsupportedThenErrorIsSentInRedirectURIQueryParameter() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		OAuth2AuthorizationEndpointFilter spyFilter = spy(this.filter);
		spyFilter.doFilter(request, response, filterChain);

		verify(spyFilter, times(1)).shouldNotFilter(any(HttpServletRequest.class));
		verify(spyFilter, times(0)).doFilterInternal(any(HttpServletRequest.class), any(HttpServletResponse.class), any(FilterChain.class));
		verify(filterChain, times(1)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	private MockHttpServletRequest getValidMockHttpServletRequest() {

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, VALID_CLIENT);
		request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "code");
		request.setParameter(OAuth2ParameterNames.SCOPE, "openid profile email");
		request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "http://localhost:8080/test-application/callback");
		request.setParameter(OAuth2ParameterNames.STATE, "teststate");
		request.setServletPath("/oauth2/authorize");

		return request;


	}

}
