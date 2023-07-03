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
package sample.extgrant;

import java.util.UUID;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	// @formatter:off
	@Bean
	SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http,
			OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();

		authorizationServerConfigurer
			.tokenEndpoint(tokenEndpoint ->
				tokenEndpoint
					.accessTokenRequestConverter( // <1>
						new CustomCodeGrantAuthenticationConverter())
					.authenticationProvider( // <2>
						new CustomCodeGrantAuthenticationProvider(
							authorizationService, tokenGenerator)));

		// @fold:on
		RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

		http
			.securityMatcher(endpointsMatcher)
			.authorizeHttpRequests(authorize ->
				authorize
					.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.apply(authorizationServerConfigurer);
		// @fold:off

		return http.build();
	}
	// @formatter:on

	// @fold:on
	// @formatter:off
	@Bean
	RegisteredClientRepository registeredClientRepository() {
		RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:custom_code"))
				.scope("message.read")
				.scope("message.write")
				.build();

		return new InMemoryRegisteredClientRepository(messagingClient);
	}
	// @formatter:on

	@Bean
	OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(
				jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}
	// @fold:off

}
