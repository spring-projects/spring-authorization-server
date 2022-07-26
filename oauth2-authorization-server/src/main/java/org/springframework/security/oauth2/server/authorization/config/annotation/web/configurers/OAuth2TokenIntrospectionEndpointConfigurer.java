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

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for the OAuth 2.0 Token Introspection Endpoint.
 *
 * @author Gaurav Tiwari
 * @since 0.2.3
 * @see OAuth2AuthorizationServerConfigurer#tokenIntrospectionEndpoint(Customizer)
 * @see OAuth2TokenIntrospectionEndpointFilter
 */
public final class OAuth2TokenIntrospectionEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private AuthenticationConverter introspectionRequestConverter;
	private final List<AuthenticationProvider> authenticationProviders = new LinkedList<>();
	private AuthenticationSuccessHandler introspectionResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2TokenIntrospectionEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Introspection Request from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2TokenIntrospectionAuthenticationToken} used for authenticating the request.
	 *
	 * @param introspectionRequestConverter the {@link AuthenticationConverter} used when attempting to extract an Introspection Request from {@link HttpServletRequest}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer introspectionRequestConverter(AuthenticationConverter introspectionRequestConverter) {
		this.introspectionRequestConverter = introspectionRequestConverter;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2TokenIntrospectionAuthenticationToken}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2TokenIntrospectionAuthenticationToken}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2TokenIntrospectionAuthenticationToken}.
	 *
	 * @param introspectionResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2TokenIntrospectionAuthenticationToken}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer introspectionResponseHandler(AuthenticationSuccessHandler introspectionResponseHandler) {
		this.introspectionResponseHandler = introspectionResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OAuth2TokenIntrospectionEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenIntrospectionEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		this.requestMatcher = new AntPathRequestMatcher(
				providerSettings.getTokenIntrospectionEndpoint(), HttpMethod.POST.name());

		List<AuthenticationProvider> authenticationProviders =
				!this.authenticationProviders.isEmpty() ?
						this.authenticationProviders :
						createDefaultAuthenticationProviders(builder);
		authenticationProviders.forEach(authenticationProvider ->
				builder.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);

		OAuth2TokenIntrospectionEndpointFilter introspectionEndpointFilter =
				new OAuth2TokenIntrospectionEndpointFilter(
						authenticationManager, providerSettings.getTokenIntrospectionEndpoint());
		if (this.introspectionRequestConverter != null) {
			introspectionEndpointFilter.setAuthenticationConverter(this.introspectionRequestConverter);
		}
		if (this.introspectionResponseHandler != null) {
			introspectionEndpointFilter.setAuthenticationSuccessHandler(this.introspectionResponseHandler);
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

		OAuth2TokenIntrospectionAuthenticationProvider tokenIntrospectionAuthenticationProvider =
				new OAuth2TokenIntrospectionAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
						OAuth2ConfigurerUtils.getAuthorizationService(builder));
		authenticationProviders.add(tokenIntrospectionAuthenticationProvider);

		return authenticationProviders;
	}

}
