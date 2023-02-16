/*
 * Copyright 2020-2023 the original author or authors.
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

import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContext;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OpenID Connect 1.0 Provider Configuration endpoint.
 *
 * @author Sahariar Alam Khandoker
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringTestContextExtension.class)
public class OidcProviderConfigurationTests {
	private static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";
	private static final String ISSUER_URL = "https://example.com/issuer1";

	public final SpringTestContext spring = new SpringTestContext();

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenConfigurationRequestAndIssuerSetThenReturnDefaultConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(defaultConfigurationMatchers());
	}

	// gh-632
	@Test
	public void requestWhenConfigurationRequestAndUserAuthenticatedThenReturnConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI)
				.with(user("user")))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(defaultConfigurationMatchers());
	}

	// gh-616
	@Test
	public void requestWhenConfigurationRequestAndConfigurationCustomizerSetThenReturnCustomConfigurationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithProviderConfigurationCustomizer.class).autowire();

		this.mvc.perform(get(DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpect(jsonPath(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED,
						hasItems(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL)));
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
				jsonPath("end_session_endpoint").value(ISSUER_URL.concat(this.authorizationServerSettings.getOidcLogoutEndpoint())),
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

	@Test
	public void loadContextWhenIssuerWithQueryThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerQuery.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithFragmentThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerFragment.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithQueryAndFragmentThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerQueryAndFragment.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithEmptyQueryThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerEmptyQuery.class).autowire()
		);
	}

	@Test
	public void loadContextWhenIssuerWithEmptyFragmentThenThrowException() {
		assertThatThrownBy(
				() -> this.spring.register(AuthorizationServerConfigurationWithIssuerEmptyFragment.class).autowire()
		);
	}

	@EnableWebSecurity
	static class AuthorizationServerConfiguration {

		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
			http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
					.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
			return http.build();
		}

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

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithProviderConfigurationCustomizer extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer();
			http.apply(authorizationServerConfigurer);

			authorizationServerConfigurer
					.oidc(oidc ->
							oidc.providerConfigurationEndpoint(providerConfigurationEndpoint ->
									providerConfigurationEndpoint
											.providerConfigurationCustomizer(providerConfigurationCustomizer())));

			RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

			http
					.securityMatcher(endpointsMatcher)
					.authorizeHttpRequests(authorize ->
							authorize.anyRequest().authenticated()
					)
					.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher));

			return http.build();
		}
		// @formatter:on

		private Consumer<OidcProviderConfiguration.Builder> providerConfigurationCustomizer() {
			return (providerConfiguration) ->
					providerConfiguration.scope(OidcScopes.PROFILE).scope(OidcScopes.EMAIL);
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
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

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithInvalidIssuerUrl extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer("urn:example").build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithInvalidIssuerUri extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer("https://not a valid uri").build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithIssuerQuery extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER_URL + "?param=value").build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithIssuerFragment extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER_URL + "#fragment").build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithIssuerQueryAndFragment extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER_URL + "?param=value#fragment").build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithIssuerEmptyQuery extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER_URL + "?").build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithIssuerEmptyFragment extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().issuer(ISSUER_URL + "#").build();
		}
	}

}
