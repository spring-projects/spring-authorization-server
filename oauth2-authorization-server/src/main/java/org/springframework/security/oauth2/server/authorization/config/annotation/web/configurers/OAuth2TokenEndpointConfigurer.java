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
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for the OAuth 2.0 Token Endpoint.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see OAuth2AuthorizationServerConfigurer#tokenEndpoint
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2TokenEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private AuthenticationConverter accessTokenRequestConverter;
	private final List<AuthenticationProvider> authenticationProviders = new LinkedList<>();
	private AuthenticationSuccessHandler accessTokenResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2TokenEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationGrantAuthenticationToken} used for authenticating the authorization grant.
	 *
	 * @param accessTokenRequestConverter the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer accessTokenRequestConverter(AuthenticationConverter accessTokenRequestConverter) {
		this.accessTokenRequestConverter = accessTokenRequestConverter;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2AuthorizationGrantAuthenticationToken}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2AuthorizationGrantAuthenticationToken}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AccessTokenAuthenticationToken}
	 * and returning the {@link OAuth2AccessTokenResponse Access Token Response}.
	 *
	 * @param accessTokenResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AccessTokenAuthenticationToken}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer accessTokenResponseHandler(AuthenticationSuccessHandler accessTokenResponseHandler) {
		this.accessTokenResponseHandler = accessTokenResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
	 */
	public OAuth2TokenEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(httpSecurity);
		this.requestMatcher = new AntPathRequestMatcher(
				providerSettings.getTokenEndpoint(), HttpMethod.POST.name());

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
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(httpSecurity);

		OAuth2TokenEndpointFilter tokenEndpointFilter =
				new OAuth2TokenEndpointFilter(
						authenticationManager,
						providerSettings.getTokenEndpoint());
		if (this.accessTokenRequestConverter != null) {
			tokenEndpointFilter.setAuthenticationConverter(this.accessTokenRequestConverter);
		}
		if (this.accessTokenResponseHandler != null) {
			tokenEndpointFilter.setAuthenticationSuccessHandler(this.accessTokenResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			tokenEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(tokenEndpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);

		OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
				new OAuth2AuthorizationCodeAuthenticationProvider(authorizationService, tokenGenerator);
		authenticationProviders.add(authorizationCodeAuthenticationProvider);

		OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider =
				new OAuth2RefreshTokenAuthenticationProvider(authorizationService, tokenGenerator);
		authenticationProviders.add(refreshTokenAuthenticationProvider);

		OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider =
				new OAuth2ClientCredentialsAuthenticationProvider(authorizationService, tokenGenerator);
		authenticationProviders.add(clientCredentialsAuthenticationProvider);

		return authenticationProviders;
	}

}
