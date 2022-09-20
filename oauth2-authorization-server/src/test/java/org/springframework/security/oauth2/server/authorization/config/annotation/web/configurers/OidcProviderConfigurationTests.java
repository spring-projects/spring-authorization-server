/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.test.SpringTestRule;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OpenID Connect 1.0 Provider Configuration endpoint.
 *
 * @author Sahariar Alam Khandoker
 * @author Joe Grandja
 */
public class OidcProviderConfigurationTests {
	private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";
	private static final String ISSUER_URL = "https://example.com/issuer1";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenConfigurationRequestThenDefaultConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(defaultConfigurationMatchers())
				.andExpect(jsonPath("$.registration_endpoint").doesNotExist());
	}

	@Test
	public void requestWhenConfigurationRequestAndClientRegistrationEnabledThenConfigurationResponseIncludesRegistrationEndpoint() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithClientRegistrationEnabled.class).autowire();

		this.mvc.perform(get(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(defaultConfigurationMatchers())
				.andExpect(jsonPath("$.registration_endpoint").value(ISSUER_URL.concat(this.authorizationServerSettings.getOidcClientRegistrationEndpoint())));
	}

	private ResultMatcher[] defaultConfigurationMatchers() {
		// @formatter:off
		return new ResultMatcher[] {
				jsonPath("issuer").value(ISSUER_URL),
				jsonPath("authorization_endpoint").value(ISSUER_URL.concat(this.authorizationServerSettings.getAuthorizationEndpoint())),
				jsonPath("token_endpoint").value(ISSUER_URL.concat(this.authorizationServerSettings.getTokenEndpoint())),
				jsonPath("$.token_endpoint_auth_methods_supported[0]").value(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()),
				jsonPath("$.token_endpoint_auth_methods_supported[1]").value(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()),
				jsonPath("$.token_endpoint_auth_methods_supported[2]").value(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()),
				jsonPath("$.token_endpoint_auth_methods_supported[3]").value(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()),
				jsonPath("jwks_uri").value(ISSUER_URL.concat(this.authorizationServerSettings.getJwkSetEndpoint())),
				jsonPath("userinfo_endpoint").value(ISSUER_URL.concat(this.authorizationServerSettings.getOidcUserInfoEndpoint())),
				jsonPath("response_types_supported").value(OAuth2AuthorizationResponseType.CODE.getValue()),
				jsonPath("$.grant_types_supported[0]").value(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				jsonPath("$.grant_types_supported[1]").value(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()),
				jsonPath("$.grant_types_supported[2]").value(AuthorizationGrantType.REFRESH_TOKEN.getValue()),
				jsonPath("revocation_endpoint").value(ISSUER_URL.concat(this.authorizationServerSettings.getTokenRevocationEndpoint())),
				jsonPath("$.revocation_endpoint_auth_methods_supported[0]").value(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()),
				jsonPath("$.revocation_endpoint_auth_methods_supported[1]").value(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()),
				jsonPath("$.revocation_endpoint_auth_methods_supported[2]").value(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()),
				jsonPath("$.revocation_endpoint_auth_methods_supported[3]").value(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()),
				jsonPath("introspection_endpoint").value(ISSUER_URL.concat(this.authorizationServerSettings.getTokenIntrospectionEndpoint())),
				jsonPath("$.introspection_endpoint_auth_methods_supported[0]").value(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()),
				jsonPath("$.introspection_endpoint_auth_methods_supported[1]").value(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()),
				jsonPath("$.introspection_endpoint_auth_methods_supported[2]").value(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()),
				jsonPath("$.introspection_endpoint_auth_methods_supported[3]").value(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()),
				jsonPath("subject_types_supported").value("public"),
				jsonPath("id_token_signing_alg_values_supported").value(SignatureAlgorithm.RS256.getName()),
				jsonPath("scopes_supported").value(OidcScopes.OPENID)
		};
		// @formatter:on
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
			return new InMemoryRegisteredClientRepository(registeredClient);
		}

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder()
					.issuer(ISSUER_URL)
					.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithClientRegistrationEnabled extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer();
			http.apply(authorizationServerConfigurer);

			authorizationServerConfigurer
					.oidc(oidc ->
							oidc.clientRegistrationEndpoint(Customizer.withDefaults())
					);

			return http.build();
		}
		// @formatter:on

	}

}
