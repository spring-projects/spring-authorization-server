package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.test.SpringTestRule;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.springframework.test.web.servlet.ResultMatcher.matchAll;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OpenID Provider Configuration Endpoint.
 *
 * @author Sahariar Alam Khandoker
 */
public class OidcProviderConfigurationMetaDataTests {
	private static final String DEFAULT_OAUTH2_PROVIDER_CONFIGURATION_METADATA_ENDPOINT_URI = "/.well-known/openid-configuration";
	private static final String issuerUrl = "https://example.com/issuer1";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenProviderConfigurationRequestGetTheProviderConfigurationResponseWithoutRegistrationEndpoint() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(DEFAULT_OAUTH2_PROVIDER_CONFIGURATION_METADATA_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpect(providerConfigurationResponse())
				.andExpect(jsonPath("$.registration_endpoint").doesNotExist())
				.andReturn();
	}

	@Test
	public void requestWhenProviderConfigurationWithClientRegistrationEnabledRequestGetTheProviderConfigurationResponseWithRegistrationEndpoint() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithClientRegistrationEnabled.class).autowire();

		this.mvc.perform(get(DEFAULT_OAUTH2_PROVIDER_CONFIGURATION_METADATA_ENDPOINT_URI))
				.andExpect(status().is2xxSuccessful())
				.andExpect(providerConfigurationResponse())
				.andExpect(jsonPath("$.registration_endpoint").value("https://example.com/issuer1/connect/register"))
				.andReturn();
	}

	private static ResultMatcher providerConfigurationResponse() {
		// @formatter:off
		return matchAll(
				jsonPath("issuer").value("https://example.com/issuer1"),
				jsonPath("authorization_endpoint").value("https://example.com/issuer1/oauth2/authorize"),
				jsonPath("token_endpoint").value("https://example.com/issuer1/oauth2/token"),
				jsonPath("jwks_uri").value("https://example.com/issuer1/oauth2/jwks"),
				jsonPath("scopes_supported").value("openid"),
				jsonPath("response_types_supported").value("code"),
				jsonPath("$.grant_types_supported[0]").value("authorization_code"),
				jsonPath("$.grant_types_supported[1]").value("client_credentials"),
				jsonPath("$.grant_types_supported[2]").value("refresh_token"),
				jsonPath("revocation_endpoint").value("https://example.com/issuer1/oauth2/revoke"),
				jsonPath("$.revocation_endpoint_auth_methods_supported[0]").value("client_secret_basic"),
				jsonPath("$.revocation_endpoint_auth_methods_supported[1]").value("client_secret_post"),
				jsonPath("$.revocation_endpoint_auth_methods_supported[2]").value("client_secret_jwt"),
				jsonPath("$.revocation_endpoint_auth_methods_supported[3]").value("private_key_jwt"),
				jsonPath("introspection_endpoint").value("https://example.com/issuer1/oauth2/introspect"),
				jsonPath("$.introspection_endpoint_auth_methods_supported[0]").value("client_secret_basic"),
				jsonPath("$.introspection_endpoint_auth_methods_supported[1]").value("client_secret_post"),
				jsonPath("$.introspection_endpoint_auth_methods_supported[2]").value("client_secret_jwt"),
				jsonPath("$.introspection_endpoint_auth_methods_supported[3]").value("private_key_jwt"),
				jsonPath("subject_types_supported").value("public"),
				jsonPath("id_token_signing_alg_values_supported").value("RS256"),
				jsonPath("userinfo_endpoint").value("https://example.com/issuer1/userinfo"),
				jsonPath("$.token_endpoint_auth_methods_supported[0]").value("client_secret_basic"),
				jsonPath("$.token_endpoint_auth_methods_supported[1]").value("client_secret_post"),
				jsonPath("$.token_endpoint_auth_methods_supported[2]").value("client_secret_jwt"),
				jsonPath("$.token_endpoint_auth_methods_supported[3]").value("private_key_jwt")
		);
		// @formatter:on
	}


	@EnableWebSecurity
	static class AuthorizationServerConfigurationWithClientRegistrationEnabled extends AuthorizationServerConfiguration {
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
					new OAuth2AuthorizationServerConfigurer();
			http.apply(authorizationServerConfigurer);

			authorizationServerConfigurer
					.oidc(oidc ->
							oidc
									.clientRegistrationEndpoint(Customizer.withDefaults())
					);

			return http.build();
		}
	}

	@EnableWebSecurity
	static class AuthorizationServerConfiguration {

		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
			// @formatter:off
			http
					.exceptionHandling(exceptions ->
							exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
					);
			// @formatter:on
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
					.issuer(issuerUrl)
					.build();
		}

	}

}
