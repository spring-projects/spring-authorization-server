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

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OidcProviderConfigurationEndpointFilter}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OidcProviderConfigurationEndpointFilterTests {
	private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";

	@Test
	public void constructorWhenProviderSettingsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcProviderConfigurationEndpointFilter(null))
				.withMessage("providerSettings cannot be null");
	}

	@Test
	public void doFilterWhenNotConfigurationRequestThenNotProcessed() throws Exception {
		OidcProviderConfigurationEndpointFilter filter =
				new OidcProviderConfigurationEndpointFilter(ProviderSettings.builder().build());

		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenConfigurationRequestPostThenNotProcessed() throws Exception {
		OidcProviderConfigurationEndpointFilter filter =
				new OidcProviderConfigurationEndpointFilter(ProviderSettings.builder().build());

		String requestUri = DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenConfigurationRequestThenConfigurationResponse() throws Exception {
		String authorizationEndpoint = "/oauth2/v1/authorize";
		String tokenEndpoint = "/oauth2/v1/token";
		String jwkSetEndpoint = "/oauth2/v1/jwks";

		ProviderSettings providerSettings = ProviderSettings.builder()
				.issuer("https://example.com/issuer1")
				.authorizationEndpoint(authorizationEndpoint)
				.tokenEndpoint(tokenEndpoint)
				.jwkSetEndpoint(jwkSetEndpoint)
				.build();
		OidcProviderConfigurationEndpointFilter filter =
				new OidcProviderConfigurationEndpointFilter(providerSettings);

		String requestUri = DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		String providerConfigurationResponse = response.getContentAsString();
		assertThat(providerConfigurationResponse).contains("\"issuer\":\"https://example.com/issuer1\"");
		assertThat(providerConfigurationResponse).contains("\"authorization_endpoint\":\"https://example.com/issuer1/oauth2/v1/authorize\"");
		assertThat(providerConfigurationResponse).contains("\"token_endpoint\":\"https://example.com/issuer1/oauth2/v1/token\"");
		assertThat(providerConfigurationResponse).contains("\"jwks_uri\":\"https://example.com/issuer1/oauth2/v1/jwks\"");
		assertThat(providerConfigurationResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(providerConfigurationResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(providerConfigurationResponse).contains("\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\"]");
		assertThat(providerConfigurationResponse).contains("\"subject_types_supported\":[\"public\"]");
		assertThat(providerConfigurationResponse).contains("\"id_token_signing_alg_values_supported\":[\"RS256\"]");
		assertThat(providerConfigurationResponse).contains("\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"]");
	}

	@Test
	public void doFilterWhenProviderSettingsWithInvalidIssuerThenThrowIllegalArgumentException() {
		ProviderSettings providerSettings = ProviderSettings.builder()
				.issuer("https://this is an invalid URL")
				.build();
		OidcProviderConfigurationEndpointFilter filter =
				new OidcProviderConfigurationEndpointFilter(providerSettings);

		String requestUri = DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		assertThatIllegalArgumentException()
				.isThrownBy(() -> filter.doFilter(request, response, filterChain))
				.withMessage("issuer must be a valid URL");
	}
}
