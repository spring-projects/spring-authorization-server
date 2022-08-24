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
import java.util.LinkedList;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for the OAuth 2.0 Token Revocation Endpoint.
 *
 * @author Arfat Chaus
 * @since 0.2.2
 * @see OAuth2AuthorizationServerConfigurer#tokenRevocationEndpoint
 * @see OAuth2TokenRevocationEndpointFilter
 */
public final class OAuth2TokenRevocationEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private AuthenticationConverter revocationRequestConverter;
	private final List<AuthenticationProvider> authenticationProviders = new LinkedList<>();
	private AuthenticationSuccessHandler revocationResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2TokenRevocationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Revoke Token Request from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2TokenRevocationAuthenticationToken} used for authenticating the client.
	 *
	 * @param revocationRequestConverter the {@link AuthenticationConverter} used when attempting to extract client credentials from {@link HttpServletRequest}
	 * @return the {@link OAuth2TokenRevocationEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenRevocationEndpointConfigurer revocationRequestConverter(AuthenticationConverter revocationRequestConverter) {
		this.revocationRequestConverter = revocationRequestConverter;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2TokenRevocationAuthenticationToken}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2TokenRevocationAuthenticationToken}
	 * @return the {@link OAuth2TokenRevocationEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenRevocationEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2TokenRevocationAuthenticationToken}.
	 *
	 * @param revocationResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2TokenRevocationAuthenticationToken}
	 * @return the {@link OAuth2TokenRevocationEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenRevocationEndpointConfigurer revocationResponseHandler(AuthenticationSuccessHandler revocationResponseHandler) {
		this.revocationResponseHandler = revocationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OAuth2TokenRevocationEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenRevocationEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		this.requestMatcher = new AntPathRequestMatcher(
				authorizationServerSettings.getTokenRevocationEndpoint(), HttpMethod.POST.name());

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
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);

		OAuth2TokenRevocationEndpointFilter revocationEndpointFilter =
				new OAuth2TokenRevocationEndpointFilter(
						authenticationManager, authorizationServerSettings.getTokenRevocationEndpoint());
		if (this.revocationRequestConverter != null) {
			revocationEndpointFilter.setAuthenticationConverter(this.revocationRequestConverter);
		}
		if (this.revocationResponseHandler != null) {
			revocationEndpointFilter.setAuthenticationSuccessHandler(this.revocationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			revocationEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(revocationEndpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2TokenRevocationAuthenticationProvider tokenRevocationAuthenticationProvider =
				new OAuth2TokenRevocationAuthenticationProvider(OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
		authenticationProviders.add(tokenRevocationAuthenticationProvider);

		return authenticationProviders;
	}

}
