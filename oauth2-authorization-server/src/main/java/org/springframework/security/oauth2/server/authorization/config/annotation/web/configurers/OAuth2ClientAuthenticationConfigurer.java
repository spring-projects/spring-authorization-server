/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.PublicClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for OAuth 2.0 Client Authentication.
 *
 * @author Joe Grandja
 * @since 0.2.0
 * @see OAuth2AuthorizationServerConfigurer#clientAuthentication
 * @see OAuth2ClientAuthenticationFilter
 */
public final class OAuth2ClientAuthenticationConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private AuthenticationConverter authenticationConverter;
	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
	private AuthenticationSuccessHandler authenticationSuccessHandler;
	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2ClientAuthenticationConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract client credentials from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
	 *
	 * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract client credentials from {@link HttpServletRequest}
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationConverter(AuthenticationConverter authenticationConverter) {
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an {@link OAuth2ClientAuthenticationToken}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating an {@link OAuth2ClientAuthenticationToken}
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling a successful client authentication
	 * and associating the {@link OAuth2ClientAuthenticationToken} to the {@link SecurityContext}.
	 *
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling a successful client authentication
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer authenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling a failed client authentication
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling a failed client authentication
	 * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
	 */
	public OAuth2ClientAuthenticationConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		this.requestMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(
						authorizationServerSettings.getTokenEndpoint(),
						HttpMethod.POST.name()),
				new AntPathRequestMatcher(
						authorizationServerSettings.getTokenIntrospectionEndpoint(),
						HttpMethod.POST.name()),
				new AntPathRequestMatcher(
						authorizationServerSettings.getTokenRevocationEndpoint(),
						HttpMethod.POST.name()));

		List<AuthenticationProvider> authenticationProviders =
				!this.authenticationProviders.isEmpty() ?
						this.authenticationProviders :
						createDefaultAuthenticationProviders(httpSecurity);
		authenticationProviders.forEach(authenticationProvider ->
				httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		OAuth2ClientAuthenticationFilter clientAuthenticationFilter = new OAuth2ClientAuthenticationFilter(
				authenticationManager, this.requestMatcher);
		if (this.authenticationConverter != null) {
			clientAuthenticationFilter.setAuthenticationConverter(this.authenticationConverter);
		}
		if (this.authenticationSuccessHandler != null) {
			clientAuthenticationFilter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
		}
		if (this.errorResponseHandler != null) {
			clientAuthenticationFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		RegisteredClientRepository registeredClientRepository = OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity);
		OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);

		JwtClientAssertionAuthenticationProvider jwtClientAssertionAuthenticationProvider =
				new JwtClientAssertionAuthenticationProvider(registeredClientRepository, authorizationService);
		authenticationProviders.add(jwtClientAssertionAuthenticationProvider);

		ClientSecretAuthenticationProvider clientSecretAuthenticationProvider =
				new ClientSecretAuthenticationProvider(registeredClientRepository, authorizationService);
		PasswordEncoder passwordEncoder = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, PasswordEncoder.class);
		if (passwordEncoder != null) {
			clientSecretAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		}
		authenticationProviders.add(clientSecretAuthenticationProvider);

		PublicClientAuthenticationProvider publicClientAuthenticationProvider =
				new PublicClientAuthenticationProvider(registeredClientRepository, authorizationService);
		authenticationProviders.add(publicClientAuthenticationProvider);

		return authenticationProviders;
	}

}
