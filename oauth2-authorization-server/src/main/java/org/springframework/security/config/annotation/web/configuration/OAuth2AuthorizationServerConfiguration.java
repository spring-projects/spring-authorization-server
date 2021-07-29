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
package org.springframework.security.config.annotation.web.configuration;

import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * {@link Configuration} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationServerConfigurer
 */
@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		applyDefaultSecurity(http);
		return http.build();
	}

	// @formatter:off
	public static void applyDefaultSecurity(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();

		http
			.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
			.apply(authorizationServerConfigurer);
	}
	// @formatter:on

	@Bean
	public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
		jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
		jwsAlgs.addAll(JWSAlgorithm.Family.EC);
		jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		JWSKeySelector<SecurityContext> jwsKeySelector =
				new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		// Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead
		jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
		});
		return new NimbusJwtDecoder(jwtProcessor);
	}

	@Bean
	RegisterMissingBeanPostProcessor registerMissingBeanPostProcessor() {
		RegisterMissingBeanPostProcessor postProcessor = new RegisterMissingBeanPostProcessor();
		postProcessor.addBeanDefinition(ProviderSettings.class, () -> ProviderSettings.builder().build());
		return postProcessor;
	}

}
