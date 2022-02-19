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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Configurer for OAuth 2.0 Token Introspection.
 *
 * @author Gaurav Tiwari
 * @since 0.2.3
 */
public class OAuth2TokenIntrospectionConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;
	private AuthenticationConverter accessTokenRequestConverter;
	private final List<AuthenticationProvider> authenticationProviders = new LinkedList<>();
	private AuthenticationSuccessHandler tokenIntrospectionResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2TokenIntrospectionConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationGrantAuthenticationToken} used for authenticating the authorization grant.
	 *
	 * @param accessTokenRequestConverter the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
	 * @return the {@link OAuth2TokenIntrospectionConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionConfigurer accessTokenRequestConverter(AuthenticationConverter accessTokenRequestConverter) {
		this.accessTokenRequestConverter = accessTokenRequestConverter;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2TokenIntrospectionAuthenticationToken}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2TokenIntrospectionAuthenticationToken}
	 * @return the {@link OAuth2TokenIntrospectionConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2TokenIntrospectionAuthenticationToken}.
	 *
	 * @param tokenIntrospectionResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2TokenIntrospectionAuthenticationToken}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionConfigurer accessTokenResponseHandler(AuthenticationSuccessHandler tokenIntrospectionResponseHandler) {
		this.tokenIntrospectionResponseHandler = tokenIntrospectionResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link org.springframework.security.oauth2.core.OAuth2AuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link org.springframework.security.oauth2.core.OAuth2AuthenticationException}
	 * @return the {@link OAuth2TokenIntrospectionConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		this.requestMatcher = new AntPathRequestMatcher(
				providerSettings.getTokenIntrospectionEndpoint(), HttpMethod.POST.name());

		List<AuthenticationProvider> authenticationProviders = this.authenticationProviders.isEmpty() ? createDefaultAuthenticationProviders(builder) : this.authenticationProviders;
		authenticationProviders.forEach(authenticationProvider -> builder.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);

		OAuth2TokenIntrospectionEndpointFilter introspectionEndpointFilter =
				new OAuth2TokenIntrospectionEndpointFilter(authenticationManager, providerSettings.getTokenIntrospectionEndpoint());

		if (accessTokenRequestConverter != null) {
			introspectionEndpointFilter.setAuthenticationConverter(this.accessTokenRequestConverter);
		}

		if (this.tokenIntrospectionResponseHandler != null) {
			introspectionEndpointFilter.setAuthenticationSuccessHandler(this.tokenIntrospectionResponseHandler);
		}

		if (this.errorResponseHandler != null) {
			introspectionEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}

		builder.addFilterAfter(postProcess(introspectionEndpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private <B extends HttpSecurityBuilder<B>> List<AuthenticationProvider> createDefaultAuthenticationProviders(B builder) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2TokenIntrospectionAuthenticationProvider tokenIntrospectionAuthenticationProvider
				= new OAuth2TokenIntrospectionAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
				OAuth2ConfigurerUtils.getAuthorizationService(builder)
		);

		authenticationProviders.add(tokenIntrospectionAuthenticationProvider);

		return authenticationProviders;

	}
}
