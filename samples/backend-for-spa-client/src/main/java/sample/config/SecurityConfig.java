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

import java.util.LinkedHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author Joe Grandja
 * @since 1.4
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

	@Value("${app.base-uri}")
	private String appBaseUri;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
		/*
		IMPORTANT:
		Set the csrfRequestAttributeName to null, to opt-out of deferred tokens, resulting in the CsrfToken to be loaded on every request.
		If it does not exist, the CookieCsrfTokenRepository will automatically generate a new one and add the Cookie to the response.
		See the reference: https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#deferred-csrf-token
		 */
		csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName(null);

		// @formatter:off
		http
			.authorizeHttpRequests(authorize ->
				authorize
					.anyRequest().authenticated()
			)
			.csrf(csrf ->
				csrf
					.csrfTokenRepository(cookieCsrfTokenRepository)
					.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
			)
			.cors(Customizer.withDefaults())
			.exceptionHandling(exceptionHandling ->
				exceptionHandling
					.authenticationEntryPoint(authenticationEntryPoint())
			)
			.oauth2Login(oauth2Login ->
				oauth2Login
					.successHandler(new SimpleUrlAuthenticationSuccessHandler(this.appBaseUri)))
			.logout(logout ->
				logout
					.addLogoutHandler(logoutHandler(cookieCsrfTokenRepository))
					.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
			)
			.oauth2Client(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	private AuthenticationEntryPoint authenticationEntryPoint() {
		AuthenticationEntryPoint authenticationEntryPoint =
				new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/messaging-client-oidc");
		MediaTypeRequestMatcher textHtmlMatcher =
				new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		textHtmlMatcher.setUseEquals(true);

		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
		entryPoints.put(textHtmlMatcher, authenticationEntryPoint);

		DelegatingAuthenticationEntryPoint delegatingAuthenticationEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
		delegatingAuthenticationEntryPoint.setDefaultEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
		return delegatingAuthenticationEntryPoint;
	}

	private LogoutHandler logoutHandler(CsrfTokenRepository csrfTokenRepository) {
		return new CompositeLogoutHandler(
				new SecurityContextLogoutHandler(),
				new CsrfLogoutHandler(csrfTokenRepository));
	}

}
