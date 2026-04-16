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
package sample.registration;

import java.util.List;
import java.util.function.Consumer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationValidator;
import org.springframework.security.web.SecurityFilterChain;

import static sample.registration.CustomClientMetadataConfig.configureCustomClientMetadataConverters;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				OAuth2AuthorizationServerConfigurer.authorizationServer();

		// @formatter:off
		http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
				authorizationServer
					.oidc((oidc) ->
						oidc.clientRegistrationEndpoint((clientRegistrationEndpoint) ->	// <1>
							clientRegistrationEndpoint
								.authenticationProviders(scopePermissiveValidatorCustomizer().andThen(configureCustomClientMetadataConverters()))	// <2>
						)
					)
			)
			.authorizeHttpRequests((authorize) ->
				authorize
					.anyRequest().authenticated()
			);
		// @formatter:on

		return http.build();
	}

	private static Consumer<List<AuthenticationProvider>> scopePermissiveValidatorCustomizer() {
		return (authenticationProviders) -> authenticationProviders.forEach((authenticationProvider) -> {
			if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
				provider.setAuthenticationValidator(
						OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.andThen(
										OidcClientRegistrationAuthenticationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
								.andThen(OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR)
								.andThen(OidcClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR));
			}
		});
	}

}
