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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

	/*
		NOTE:
		The `NimbusJwtDecoder` `@Bean` autoconfigured by Spring Boot will contain
		an `OAuth2TokenValidator<Jwt>` of type `X509CertificateThumbprintValidator`.
		This is the validator responsible for validating the `x5t#S256` claim (if available)
		in the `Jwt` against the SHA-256 Thumbprint of the supplied `X509Certificate`.
	 */

	// @formatter:off
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.securityMatcher("/messages/**")
				.authorizeHttpRequests(authorize ->
						authorize.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
						oauth2ResourceServer.jwt(Customizer.withDefaults())
				);
		return http.build();
	}
	// @formatter:on

}
