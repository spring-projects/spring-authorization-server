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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.util.OAuth2AuthorizationServerMessages;
import org.springframework.security.web.RedirectStrategy;


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

	private RedirectStrategy authorizationRedirectStrategy = mock(RedirectStrategy.class);
	private Converter<HttpServletRequest, OAuth2AuthorizationRequest> authorizationConverter = mock(Converter.class);
	private OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
	private StringKeyGenerator codeGenerator = mock(StringKeyGenerator.class);
	private RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
	private Authentication authentication = mock(Authentication.class);

	@Before
	public void setUp() {
		filter = new OAuth2AuthorizationEndpointFilter();

		filter.setAuthorizationService(authorizationService);
		filter.setCodeGenerator(codeGenerator);
		filter.setRegisteredClientRepository(registeredClientRepository);

		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@Test
	public void testFilterRedirectsWithCodeOnValidReq() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(registeredClientRepository.findByClientId(VALID_CLIENT)).thenReturn(registeredClient);
		when(codeGenerator.generateKey()).thenReturn("sample_code");
		when(authentication.isAuthenticated()).thenReturn(true);


		filter.doFilterInternal(request, response, filterChain);

		verify(authentication).isAuthenticated();
		verify(registeredClientRepository).findByClientId(VALID_CLIENT);
		verify(authorizationService).save(any(OAuth2Authorization.class));
		verify(codeGenerator).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:8080/test-application/callback?code=sample_code&state=teststate");

	}

	@Test
	public void testFilterRedirectsWithCodeToDefaultRedirectURIWhenNotPresentInRequest() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(registeredClientRepository.findByClientId(VALID_CLIENT)).thenReturn(registeredClient);
		when(codeGenerator.generateKey()).thenReturn("sample_code");
		when(authentication.isAuthenticated()).thenReturn(true);


		filter.doFilterInternal(request, response, filterChain);

		verify(authentication).isAuthenticated();
		verify(registeredClientRepository).findByClientId(VALID_CLIENT);
		verify(authorizationService).save(any(OAuth2Authorization.class));
		verify(codeGenerator).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:8080/test-application/callback?code=sample_code&state=teststate");

	}

	@Test
	public void testErrorWhenRedirectURINotPresentAndClientHasMulitipleUris() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, VALID_CLIENT_MULTI_URI);
		request.setParameter(OAuth2ParameterNames.REDIRECT_URI, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantClientMultiRedirectUris().build();
		when(registeredClientRepository.findByClientId(VALID_CLIENT_MULTI_URI)).thenReturn(registeredClient);
		when(authentication.isAuthenticated()).thenReturn(true);


		filter.doFilterInternal(request, response, filterChain);

		verify(authentication, times(1)).isAuthenticated();
		verify(registeredClientRepository, times(1)).findByClientId(VALID_CLIENT_MULTI_URI);
		verify(authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(codeGenerator, times(0)).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST+":"+OAuth2AuthorizationServerMessages.REDIRECT_URI_MANDATORY_FOR_CLIENT);

	}

	@Test
	public void testErrorClientIdNotSupportAuthorizationGrantFlow() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, VALID_CC_CLIENT);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validClientCredentialsGrantRegisteredClient().build();
		when(registeredClientRepository.findByClientId(VALID_CC_CLIENT)).thenReturn(registeredClient);
		when(authentication.isAuthenticated()).thenReturn(true);


		filter.doFilterInternal(request, response, filterChain);

		verify(authentication, times(1)).isAuthenticated();
		verify(registeredClientRepository, times(1)).findByClientId(VALID_CC_CLIENT);
		verify(authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(codeGenerator, times(0)).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED+":"+OAuth2AuthorizationServerMessages.CLIENT_ID_UNAUTHORIZED_FOR_CODE);

	}

	@Test
	public void testErrorWhenClientIdMissinInRequest() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		when(authentication.isAuthenticated()).thenReturn(true);

		filter.doFilterInternal(request, response, filterChain);

		verify(authentication).isAuthenticated();
		verify(registeredClientRepository, times(0)).findByClientId(anyString());
		verify(authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(codeGenerator, times(0)).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
		assertThat(response.getContentAsString()).isEmpty();
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST+":"+OAuth2AuthorizationServerMessages.REQUEST_MISSING_CLIENT_ID);

	}

	@Test
	public void testErrorWhenUnregisteredClientInRequest() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.CLIENT_ID, "unregistered_client");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(registeredClientRepository.findByClientId("unregistered_client")).thenReturn(null);
		when(codeGenerator.generateKey()).thenReturn("sample_code");
		when(authentication.isAuthenticated()).thenReturn(true);

		filter.doFilterInternal(request, response, filterChain);

		verify(authentication).isAuthenticated();
		verify(registeredClientRepository, times(1)).findByClientId("unregistered_client");
		verify(authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(codeGenerator, times(0)).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
		assertThat(response.getContentAsString()).isEmpty();
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED+":"+OAuth2AuthorizationServerMessages.CLIENT_ID_NOT_FOUND);

	}

	@Test
	public void testErrorWhenUnauthenticatedUserInRequest() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		when(authentication.isAuthenticated()).thenReturn(false);

		filter.doFilterInternal(request, response, filterChain);

		verify(authentication).isAuthenticated();
		verify(registeredClientRepository, times(0)).findByClientId(anyString());
		verify(authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(codeGenerator, times(0)).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
		assertThat(response.getContentAsString()).isEmpty();
		assertThat(response.getErrorMessage()).isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED+":"+OAuth2AuthorizationServerMessages.USER_NOT_AUTHENTICATED);

	}

	@Test
	public void testShouldNotFilterForUnsupportedEndpoint() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setServletPath("/custom/authorize");

		boolean willFilterGetInvoked = !filter.shouldNotFilter(request);

		assertThat(willFilterGetInvoked).isEqualTo(false);

	}

	@Test
	public void testErrorWhenResponseTypeNotPresent() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(registeredClientRepository.findByClientId(VALID_CLIENT)).thenReturn(registeredClient);
		when(codeGenerator.generateKey()).thenReturn("sample_code");
		when(authentication.isAuthenticated()).thenReturn(true);


		filter.doFilterInternal(request, response, filterChain);

		verify(authentication).isAuthenticated();
		verify(registeredClientRepository, times(1)).findByClientId(VALID_CLIENT);
		verify(authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(codeGenerator, times(0)).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).startsWith(request.getParameter(OAuth2ParameterNames.REDIRECT_URI));
		assertThat(response.getRedirectedUrl()).contains("error="+OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE);
		assertThat(URLDecoder.decode(response.getRedirectedUrl(), StandardCharsets.UTF_8.toString())).contains("error_description="+OAuth2AuthorizationServerMessages.RESPONSE_TYPE_MISSING_OR_INVALID);

	}

	@Test
	public void testErrorWhenResponseTypeIsUnsupported() throws Exception {
		MockHttpServletRequest request = getValidMockHttpServletRequest();
		request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = TestRegisteredClients.validAuthorizationGrantRegisteredClient().build();
		when(registeredClientRepository.findByClientId(VALID_CLIENT)).thenReturn(registeredClient);
		when(codeGenerator.generateKey()).thenReturn("sample_code");
		when(authentication.isAuthenticated()).thenReturn(true);


		filter.doFilterInternal(request, response, filterChain);

		verify(authentication).isAuthenticated();
		verify(registeredClientRepository, times(1)).findByClientId(VALID_CLIENT);
		verify(authorizationService, times(0)).save(any(OAuth2Authorization.class));
		verify(codeGenerator, times(0)).generateKey();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).startsWith(request.getParameter(OAuth2ParameterNames.REDIRECT_URI));
		assertThat(response.getRedirectedUrl()).contains("error="+OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE);
		assertThat(URLDecoder.decode(response.getRedirectedUrl(), StandardCharsets.UTF_8.toString())).contains("error_description="+OAuth2AuthorizationServerMessages.RESPONSE_TYPE_MISSING_OR_INVALID);

	}

	@Test
	public void testSettersAreSettingProperValue() {
		OAuth2AuthorizationEndpointFilter blankFilter = new OAuth2AuthorizationEndpointFilter();

		assertThat(blankFilter.getAuthorizationRedirectStrategy()).isNotEqualTo(authorizationRedirectStrategy);
		assertThat(blankFilter.getAuthorizationRequestConverter()).isNotEqualTo(authorizationConverter);
		assertThat(blankFilter.getAuthorizationService()).isNull();
		assertThat(blankFilter.getCodeGenerator()).isNotEqualTo(codeGenerator);
		assertThat(blankFilter.getRegisteredClientRepository()).isNull();

		blankFilter.setAuthorizationRequestConverter(authorizationConverter);
		blankFilter.setAuthorizationService(authorizationService);
		blankFilter.setCodeGenerator(codeGenerator);
		blankFilter.setRegisteredClientRepository(registeredClientRepository);
		blankFilter.setAuthorizationRedirectStrategy(authorizationRedirectStrategy);

		assertThat(blankFilter.getAuthorizationRedirectStrategy()).isEqualTo(authorizationRedirectStrategy);
		assertThat(blankFilter.getAuthorizationRequestConverter()).isEqualTo(authorizationConverter);
		assertThat(blankFilter.getAuthorizationService()).isEqualTo(authorizationService);
		assertThat(blankFilter.getCodeGenerator()).isEqualTo(codeGenerator);
		assertThat(blankFilter.getRegisteredClientRepository()).isEqualTo(registeredClientRepository);
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
