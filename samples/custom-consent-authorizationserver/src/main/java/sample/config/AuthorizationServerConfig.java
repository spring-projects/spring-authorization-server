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
package sample.config;

import java.util.UUID;

import com.accesso.security.oauth2.server.authorization.authentication.AccessoAccessTokenCustomizer;
import com.accesso.security.oauth2.server.authorization.authentication.AccessoAccessTokenResponseCustomizer;
import com.accesso.security.oauth2.server.authorization.authentication.AccessoLoginUrlAuthenticationEntryPoint;
import com.accesso.security.oauth2.server.authorization.authentication.OAuth2ExternalAuthorizationCodeAuthenticationProvider;
import com.accesso.security.oauth2.server.authorization.config.ClientExternalAuthenticationConfig;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2ConfigurerUtils;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AnonymousUserGrantAuthenticationToken;
import sample.jose.Jwks;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
	private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			AccessoAccessTokenResponseCustomizer responseCustomizer,
			ClientExternalAuthenticationConfig externalAuthConfig ) throws Exception {
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		OAuth2ExternalAuthorizationCodeAuthenticationProvider externalProvider =
				new OAuth2ExternalAuthorizationCodeAuthenticationProvider(
						OAuth2ConfigurerUtils.getAuthorizationService(http), externalAuthConfig,
						OAuth2ConfigurerUtils.getJwtEncoder(http));
		authorizationServerConfigurer
				.authorizationEndpoint(authorizationEndpoint ->
						authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
				// Accesso-specific AuthProvider that handles federated authorization_codes.
				.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint.additionalAuthenticationProvider(externalProvider))
				// Accesso-specific token endpoint response - to add attributes
				.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint.accessTokenResponseHandler(responseCustomizer));

		// WIP: authorizationServerConfigurer.addConfigurer(new OAuth2ExternalAuthorizationEndpointConfigurer());

		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();

		http
			.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.apply(authorizationServerConfigurer);

		http.formLogin(Customizer.withDefaults());
		// Didn't work: http.formLogin(formLoginConfigurer -> formLoginConfigurer.loginProcessingUrl("https://some-other-sso.example/login"));

		// The login page is reached via the exception handlers use of the authenticationEntryPoint.  Normally this is
		// just an instance of LoginUrlAuthenticationEntryPoint which determines where the redirect the user so that
		// a Username/password login form can be shown.  We override that here with one that understands how to redirect
		// based on clientId to either own login page or an external OAuth2 server.
		http.exceptionHandling(exceptionHandling -> exceptionHandling
				.authenticationEntryPoint(new AccessoLoginUrlAuthenticationEntryPoint("/login", externalAuthConfig))
		);
		return http.build();
	}

	// @formatter:off
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = makeRegisteredClient("messaging-client", "messaging-client-oidc");
		RegisteredClient registeredClient_Auth0 = makeRegisteredClient("messaging-client-auth0", "oauth2");
		return new InMemoryRegisteredClientRepository(registeredClient, registeredClient_Auth0);
	}
	// @formatter:on

	// Used to generate soem client registrations for testing different client behaviors.
	// (the original demo just had 1)
	private RegisteredClient makeRegisteredClient(String clientId, String registrationId) {
		return RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(clientId)
				.clientSecret("{noop}secret-"+clientId)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(OAuth2AnonymousUserGrantAuthenticationToken.ANONYMOUS_GRANT)
				.redirectUri("http://127.0.0.1:3000/login/oauth2/code/" + registrationId)
				.redirectUri("http://127.0.0.1:3000/authorized")
				.scope(OidcScopes.OPENID)
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer("http://auth-server:9000").build();
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService() {
		// Will be used by the ConsentController
		return new InMemoryOAuth2AuthorizationConsentService();
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> oauth2TokenCustomizer() {
		// Accesso - specific token content additions.
		return new AccessoAccessTokenCustomizer();
	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AccessoAccessTokenResponseCustomizer accessoAccessTokenResponseCustomizer(JwtDecoder decoder) {
		return new AccessoAccessTokenResponseCustomizer(decoder);
	}

	// Additional Injection of security per
	// https://stackoverflow.com/questions/69484979/spring-authorization-server-how-to-use-login-form-hosted-on-a-separate-applicat/69577014#69577014

	/*
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		// @formatter:off
		http
				.exceptionHandling(exceptionHandling -> exceptionHandling
						.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("https://some-other-sso.example/login"))
				);
		// @formatter:on
		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
				.authorizeRequests(authorize -> authorize
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		// @formatter:on

		return http.build();
	}

	@Bean
	public BearerTokenResolver bearerTokenResolver() {
		DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
		bearerTokenResolver.setAllowUriQueryParameter(true);
		return bearerTokenResolver;
	}
	*/
}
