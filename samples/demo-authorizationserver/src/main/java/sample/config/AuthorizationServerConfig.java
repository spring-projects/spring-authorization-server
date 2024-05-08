/*
 * Copyright 2020-2024 the original author or authors.
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
package sample.config;

import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import sample.authentication.DeviceClientAuthenticationProvider;
import sample.federation.FederatedIdentityIdTokenCustomizer;
import sample.jose.Jwks;
import sample.web.authentication.DeviceClientAuthenticationConverter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Steve Riesenberg
 * @since 1.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http, RegisteredClientRepository registeredClientRepository,
			AuthorizationServerSettings authorizationServerSettings) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		/*
		 * This sample demonstrates the use of a public client that does not
		 * store credentials or authenticate with the authorization server.
		 *
		 * The following components show how to customize the authorization
		 * server to allow for device clients to perform requests to the
		 * OAuth 2.0 Device Authorization Endpoint and Token Endpoint without
		 * a clientId/clientSecret.
		 *
		 * CAUTION: These endpoints will not require any authentication, and can
		 * be accessed by any client that has a valid clientId.
		 *
		 * It is therefore RECOMMENDED to carefully monitor the use of these
		 * endpoints and employ any additional protections as needed, which is
		 * outside the scope of this sample.
		 */
		DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
				new DeviceClientAuthenticationConverter(
						authorizationServerSettings.getDeviceAuthorizationEndpoint());
		DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
				new DeviceClientAuthenticationProvider(registeredClientRepository);

		// @formatter:off
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
				deviceAuthorizationEndpoint.verificationUri("/activate")
			)
			.deviceVerificationEndpoint(deviceVerificationEndpoint ->
				deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
			)
			.clientAuthentication(clientAuthentication ->
				clientAuthentication
					.authenticationConverter(deviceClientAuthenticationConverter)
					.authenticationProvider(deviceClientAuthenticationProvider)
			)
			.authorizationEndpoint(authorizationEndpoint ->
				authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		// @formatter:on

		// @formatter:off
		http
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			.oauth2ResourceServer(oauth2ResourceServer ->
				oauth2ResourceServer.jwt(Customizer.withDefaults()));
		// @formatter:on
		return http.build();
	}

	// @formatter:off
	@Bean
	public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.scope("user.read")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("device-messaging-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("message.read")
				.scope("message.write")
				.build();

		RegisteredClient tokenExchangeClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("token-client")
				.clientSecret("{noop}token")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange"))
				.scope("message.read")
				.scope("message.write")
				.build();

		RegisteredClient mtlsDemoClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("mtls-demo-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
				.clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("message.read")
				.scope("message.write")
				.clientSettings(
						ClientSettings.builder()
								.x509CertificateSubjectDN("CN=demo-client-sample,OU=Spring Samples,O=Spring,C=US")
								.jwkSetUrl("http://127.0.0.1:8080/jwks")
								.build()
				)
				.tokenSettings(
						TokenSettings.builder()
								.x509CertificateBoundAccessTokens(true)
								.build()
				)
				.build();

		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(messagingClient);
		registeredClientRepository.save(deviceClient);
		registeredClientRepository.save(tokenExchangeClient);
		registeredClientRepository.save(mtlsDemoClient);

		return registeredClientRepository;
	}
	// @formatter:on

	@Bean
	public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public JdbcOAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		// Will be used by the ConsentController
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
		return new FederatedIdentityIdTokenCustomizer();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
	}

}
