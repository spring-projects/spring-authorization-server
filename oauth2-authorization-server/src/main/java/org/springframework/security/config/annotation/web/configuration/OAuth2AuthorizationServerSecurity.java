/*
 * Copyright 2020 the original author or authors.
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

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * {@link WebSecurityConfigurerAdapter} providing default security configuration for OAuth 2.0 Authorization Server.
 *
 * @author Joe Grandja
 * @since 0.0.1
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OAuth2AuthorizationServerSecurity extends WebSecurityConfigurerAdapter {

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		RequestMatcher[] endpointMatchers = authorizationServerConfigurer
				.getEndpointMatchers().toArray(new RequestMatcher[0]);

		http
			.requestMatcher(new OrRequestMatcher(endpointMatchers))
			.authorizeRequests(authorizeRequests ->
					authorizeRequests.anyRequest().authenticated()
			)
			.formLogin(withDefaults())
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointMatchers))
			.apply(authorizationServerConfigurer);
	}
	// @formatter:on
}
