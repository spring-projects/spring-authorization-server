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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OpenID Connect 1.0.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OidcTests {
	private static final String issuerUrl = "https://example.com/issuer1";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenConfigurationRequestAndIssuerSetThenReturnConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithIssuer.class).autowire();

		this.mvc.perform(get(OidcProviderConfigurationEndpointFilter.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpect(jsonPath("issuer").value(issuerUrl))
				.andReturn();
	}

	@Test
	public void requestWhenConfigurationRequestAndIssuerNotSetThenRedirectToLogin() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get(OidcProviderConfigurationEndpointFilter.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		assertThat(mvcResult.getResponse().getRedirectedUrl()).endsWith("/login");
	}

	@Test
	public void loadContextWhenIssuerNotValidUrlThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithInvalidIssuerUrl.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerNotValidUriThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithInvalidIssuerUri.class).autowire()
		);
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			return mock(RegisteredClientRepository.class);
		}

		@Bean
		CryptoKeySource keySource() {
			return mock(CryptoKeySource.class);
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithIssuer extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return new ProviderSettings().issuer(issuerUrl);
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithInvalidIssuerUrl extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return new ProviderSettings().issuer("urn:example");
		}
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithInvalidIssuerUri extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return new ProviderSettings().issuer("https://not a valid uri");
		}
	}
}
