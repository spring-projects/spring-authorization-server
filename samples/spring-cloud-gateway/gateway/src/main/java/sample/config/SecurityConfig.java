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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;

import java.net.URI;
import java.net.URISyntaxException;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author kuan shu
 * @since 0.3.1
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) throws URISyntaxException {
		http.authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
				.pathMatchers("/login", "/logout","/rs/public-page")
				.permitAll()
				.anyExchange()
				.authenticated())
				.oauth2Login(withDefaults());
		http.csrf().disable();
		RedirectServerLogoutSuccessHandler authorizationServerLogoutHandler = new RedirectServerLogoutSuccessHandler();
		authorizationServerLogoutHandler.setLogoutSuccessUrl(new URI("http://192.168.1.6:9002/logout?redirect=http://192.168.1.6:9003/rs/public-page"));
		http.logout(it -> it.logoutSuccessHandler(authorizationServerLogoutHandler));
		return http.build();
	}

}
