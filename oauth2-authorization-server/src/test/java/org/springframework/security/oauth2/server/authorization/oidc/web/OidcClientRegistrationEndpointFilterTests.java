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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.AdditionalAnswers;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OidcClientRegistrationEndpointFilter}
 *
 * @author Ovidiu Popa
 * @since 0.1.1
 */
public class OidcClientRegistrationEndpointFilterTests {

	private static final OidcClientRegistration.Builder OIDC_CLIENT_REGISTRATION = OidcClientRegistration.builder()
			.redirectUri("https://localhost:8080/client")
			.responseType("code")
			.grantType("authorization_code")
			.tokenEndpointAuthenticationMethod("basic")
			.scope("test");
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();
	private static RegisteredClientRepository registeredClientRepository;
	private static AuthenticationManager authenticationManager;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authenticationManager = mock(AuthenticationManager.class);
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authenticationManager);
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OidcClientRegistrationEndpointFilter(null,
				authenticationManager))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {

		assertThatThrownBy(() -> new OidcClientRegistrationEndpointFilter(registeredClientRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenOidcClientRegistrationUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OidcClientRegistrationEndpointFilter(registeredClientRepository, authenticationManager, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("oidcClientRegistrationUri cannot be empty");
	}

	@Test
	public void constructorWhenOidcClientRegistrationUriEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OidcClientRegistrationEndpointFilter(registeredClientRepository, authenticationManager, ""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("oidcClientRegistrationUri cannot be empty");
	}

	@Test
	public void doFilterWhenNotClientRegistrationRequestThenNotProcessed() throws Exception {
		OidcClientRegistrationEndpointFilter filter =
				new OidcClientRegistrationEndpointFilter(registeredClientRepository, authenticationManager);

		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenClientRegistrationRequestGetThenNotProcessed() throws Exception {

		OidcClientRegistrationEndpointFilter filter =
				new OidcClientRegistrationEndpointFilter(registeredClientRepository, authenticationManager);

		String requestUri = OidcClientRegistrationEndpointFilter.DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthenticationManagerThrowsOAuth2AuthenticationExceptionThenBadRequest() throws Exception {

		setSecurityContext("client-registration-token", true, "SCOPE_client.create");

		when(authenticationManager.authenticate(any(JwtAuthenticationToken.class)))
				.thenThrow(new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));

		OidcClientRegistrationEndpointFilter filter =
				new OidcClientRegistrationEndpointFilter(registeredClientRepository, authenticationManager);

		String requestUri = OidcClientRegistrationEndpointFilter.DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);

		request.setContent(convertToByteArray(OIDC_CLIENT_REGISTRATION.build()));

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void doFilterWhenClientRegistrationRequestThenClientRegistrationResponse() throws Exception {

		doNothing().when(registeredClientRepository).saveClient(any(RegisteredClient.class));
		when(authenticationManager.authenticate(any(JwtAuthenticationToken.class))).then(AdditionalAnswers.returnsFirstArg());
		setSecurityContext("client-registration-token", true, "SCOPE_client.create");

		OidcClientRegistrationEndpointFilter filter =
				new OidcClientRegistrationEndpointFilter(registeredClientRepository, authenticationManager);

		String requestUri = OidcClientRegistrationEndpointFilter.DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);

		request.setContent(convertToByteArray(OIDC_CLIENT_REGISTRATION.build()));

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		verify(authenticationManager).authenticate(any());

		ArgumentCaptor<RegisteredClient> registeredClientCaptor = ArgumentCaptor.forClass(RegisteredClient.class);
		verify(registeredClientRepository).saveClient(registeredClientCaptor.capture());

		RegisteredClient registeredClient = registeredClientCaptor.getValue();

		assertThat(response.getStatus()).isEqualTo(HttpStatus.CREATED.value());
		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

		ObjectMapper objectMapper = new ObjectMapper();
		Map<String, Object> clientRegistrationResponse = objectMapper.readerFor(Map.class)
				.readValue(response.getContentAsString());

		assertThat(clientRegistrationResponse.get(OidcClientMetadataClaimNames.CLIENT_ID))
				.isEqualTo(registeredClient.getClientId());
		assertThat((String) clientRegistrationResponse.get(OidcClientMetadataClaimNames.CLIENT_SECRET))
				.isEqualTo(registeredClient.getClientSecret());
		assertThat((List<String>) clientRegistrationResponse.get(OidcClientMetadataClaimNames.REDIRECT_URIS))
				.containsAll(registeredClient.getRedirectUris());
		assertThat(clientRegistrationResponse.get(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT))
				.isNotNull();
		assertThat(clientRegistrationResponse.get(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT))
				.isEqualTo(0.0);
		assertThat((List<String>) clientRegistrationResponse.get(OidcClientMetadataClaimNames.RESPONSE_TYPES))
				.contains(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat((List<String>) clientRegistrationResponse.get(OidcClientMetadataClaimNames.GRANT_TYPES))
				.containsAll(grantTypes(registeredClient));

		assertThat(clientRegistrationResponse.get(OidcClientMetadataClaimNames.SCOPE))
				.isEqualTo(String.join(" ", registeredClient.getScopes()));
		assertThat(clientRegistrationResponse.get(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD))
				.isEqualTo(registeredClient.getClientAuthenticationMethods().iterator().next().getValue());
	}

	private List<String> grantTypes(RegisteredClient registeredClient) {
		return registeredClient.getAuthorizationGrantTypes().stream()
				.map(AuthorizationGrantType::getValue)
				.collect(Collectors.toList());
	}

	private static void setSecurityContext(String tokenValue, boolean authenticated, String... authorities) {
		Jwt jwt = Jwt.withTokenValue(tokenValue)
				.header("alg", "none")
				.claim("sub", "client")
				.build();
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList(authorities);
		JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, grantedAuthorities);
		jwtAuthenticationToken.setAuthenticated(authenticated);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(jwtAuthenticationToken);
		SecurityContextHolder.setContext(securityContext);
	}

	private static byte[] convertToByteArray(OidcClientRegistration clientRegistration) throws JsonProcessingException {
		ObjectMapper objectMapper = new ObjectMapper();

		return objectMapper
				.writerFor(Map.class)
				.writeValueAsBytes(clientRegistration.getClaims());
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}
}
