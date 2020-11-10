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


import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2AuthorizationServerConfigurationEndpointFilter}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationServerConfigurationEndpointFilterTests {

	@Test
	public void constructorWhenProviderSettingsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2AuthorizationServerConfigurationEndpointFilter(null))
				.withMessage("providerSettings cannot be null");
	}

	@Test
	public void doFilterWhenNotAuthorizationServerConfigurationRequestThenNotProcessed() throws Exception {
		OAuth2AuthorizationServerConfigurationEndpointFilter filter =
				new OAuth2AuthorizationServerConfigurationEndpointFilter(new ProviderSettings().issuer("https://example.com"));

		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationServerConfigurationRequestPostThenNotProcessed() throws Exception {
		OAuth2AuthorizationServerConfigurationEndpointFilter filter =
				new OAuth2AuthorizationServerConfigurationEndpointFilter(new ProviderSettings().issuer("https://example.com"));

		String requestUri = OAuth2AuthorizationServerConfigurationEndpointFilter.DEFAULT_OAUTH2_AUTHORIZATION_SERVER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationServerConfigurationRequestThenAuthorizationServerConfigurationResponse() throws Exception {
		String authorizationEndpoint = "/oauth2/v1/authorize";
		String tokenEndpoint = "/oauth2/v1/token";
		String tokenRevocationEndpoint = "/oauth2/v1/revoke";
		String jwkSetEndpoint = "/oauth2/v1/jwks";

		ProviderSettings providerSettings = new ProviderSettings()
				.issuer("https://example.com/issuer1")
				.authorizationEndpoint(authorizationEndpoint)
				.tokenEndpoint(tokenEndpoint)
				.tokenRevocationEndpoint(tokenRevocationEndpoint)
				.jwkSetEndpoint(jwkSetEndpoint);
		OAuth2AuthorizationServerConfigurationEndpointFilter filter =
				new OAuth2AuthorizationServerConfigurationEndpointFilter(providerSettings);

		String requestUri = OAuth2AuthorizationServerConfigurationEndpointFilter.DEFAULT_OAUTH2_AUTHORIZATION_SERVER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		String serverConfigurationResponse = response.getContentAsString();
		assertThat(serverConfigurationResponse).contains("\"issuer\":\"https://example.com/issuer1\"");
		assertThat(serverConfigurationResponse).contains("\"authorization_endpoint\":\"https://example.com/issuer1/oauth2/v1/authorize\"");
		assertThat(serverConfigurationResponse).contains("\"token_endpoint\":\"https://example.com/issuer1/oauth2/v1/token\"");
		assertThat(serverConfigurationResponse).contains("\"revocation_endpoint\":\"https://example.com/issuer1/oauth2/v1/revoke\"");
		assertThat(serverConfigurationResponse).contains("\"jwks_uri\":\"https://example.com/issuer1/oauth2/v1/jwks\"");
		assertThat(serverConfigurationResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(serverConfigurationResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(serverConfigurationResponse).contains("\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\"]");
		assertThat(serverConfigurationResponse).contains("\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"]");
		assertThat(serverConfigurationResponse).contains("\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"]");
		assertThat(serverConfigurationResponse).contains("\"code_challenge_methods_supported\":[\"plain\",\"S256\"]");
	}

	@Test
	public void doFilterWhenProviderSettingsWithInvalidIssuerThenThrowIllegalArgumentException() {
		ProviderSettings providerSettings = new ProviderSettings()
				.issuer("https://this is an invalid URL");
		OAuth2AuthorizationServerConfigurationEndpointFilter filter =
				new OAuth2AuthorizationServerConfigurationEndpointFilter(providerSettings);

		String requestUri = OAuth2AuthorizationServerConfigurationEndpointFilter.DEFAULT_OAUTH2_AUTHORIZATION_SERVER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);


		assertThatIllegalArgumentException()
				.isThrownBy(() -> filter.doFilter(request, response, filterChain))
				.withMessage("issuer must be a valid URL");
	}
}
