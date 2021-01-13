package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.crypto.key.StaticKeyGeneratingCryptoKeySource;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.JwkSetEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests for the JWK Set requests.
 *
 * @author Florian Berthe
 */
public class JwkSetRetrievalTests {
	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static CryptoKeySource keySource;
	private static ProviderSettings providerSettings;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authorizationService = mock(OAuth2AuthorizationService.class);
		keySource = new StaticKeyGeneratingCryptoKeySource();
		providerSettings = new ProviderSettings().jwkSetEndpoint("/test/jwks");
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);
	}

	@Test
	public void requestWhenJwkSetValidThenReturnKeys() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		this.mvc.perform(get(JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
				.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
				.andExpect(jsonPath("$.keys").isNotEmpty())
				.andExpect(jsonPath("$.keys").isArray());

	}

	@Test
	public void requestWhenCustomProviderSettingsThenOk() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithProviderSettings.class).autowire();

		this.mvc.perform(get(providerSettings.jwkSetEndpoint()))
				.andExpect(status().isOk());
	}

	@Test
	public void requestWhenCustomProviderSettingsThenNotFound() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithProviderSettings.class).autowire();

		this.mvc.perform(get(JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI))
				.andExpect(status().isNotFound());
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {
		
		@Bean
		RegisteredClientRepository registeredClientRepository() {
			return registeredClientRepository;
		}

		@Bean
		OAuth2AuthorizationService authorizationService() {
			return authorizationService;
		}
		
		@Bean
		CryptoKeySource keySource() {
			return keySource;
		}
	}
	
	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithProviderSettings extends AuthorizationServerConfiguration {

		@Bean
		ProviderSettings providerSettings() {
			return providerSettings;
		}

	}
}