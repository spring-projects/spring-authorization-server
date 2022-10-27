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
import java.util.function.Consumer;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configurer for OpenID Connect 1.0 UserInfo Endpoint.
 *
 * @author Steve Riesenberg
 * @author Daniel Garnier-Moiroux
 * @since 0.2.1
 * @see OidcConfigurer#userInfoEndpoint
 * @see OidcUserInfoEndpointFilter
 */
public final class OidcUserInfoEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private final List<AuthenticationConverter> userInfoRequestConverters = new ArrayList<>();
	private Consumer<List<AuthenticationConverter>> userInfoRequestConvertersConsumer = (authenticationConverters) -> {};
	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {};
	private AuthenticationSuccessHandler userInfoResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;
	private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper;

	/**
	 * Restrict for internal use only.
	 */
	OidcUserInfoEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract the OAuth2 Access Token from {@link HttpServletRequest}
	 * to an instance of {@link OidcUserInfoAuthenticationToken} used for authenticating the User Info request.
	 *
	 * @param userInfoRequestConverter the {@link AuthenticationConverter} used when attempting to extract an OIDC User Info from {@link HttpServletRequest}
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OidcUserInfoEndpointConfigurer userInfoRequestConverter(AuthenticationConverter userInfoRequestConverter) {
		Assert.notNull(userInfoRequestConverter, "userInfoRequestConverter cannot be null");
		this.userInfoRequestConverters.add(userInfoRequestConverter);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default
	 * and (optionally) added {@link #userInfoRequestConverter(AuthenticationConverter) AuthenticationConverter}'s
	 * allowing the ability to add, remove, or customize a specific {@link AuthenticationConverter}.
	 *
	 * @param userInfoRequestConvertersConsumer the {@code Consumer} providing access to the {@code List} of default and (optionally) added {@link AuthenticationConverter}'s
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OidcUserInfoEndpointConfigurer userInfoRequestConverters(
			Consumer<List<AuthenticationConverter>> userInfoRequestConvertersConsumer) {
		Assert.notNull(userInfoRequestConvertersConsumer, "userInfoRequestConvertersConsumer cannot be null");
		this.userInfoRequestConvertersConsumer = userInfoRequestConvertersConsumer;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating a type of {@link OidcUserInfoAuthenticationToken}.
	 *
	 * @param authenticationProvider a {@link AuthenticationProvider} used for authenticating a type of {@link OidcUserInfoAuthenticationToken}
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OidcUserInfoEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@code List} of default
	 * and (optionally) added {@link #authenticationProvider(AuthenticationProvider) AuthenticationProvider}'s
	 * allowing the ability to add, remove, or customize a specific {@link AuthenticationProvider}.
	 *
	 * @param authenticationProvidersConsumer the {@code Consumer} providing access to the {@code List} of default and (optionally) added {@link AuthenticationProvider}'s
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OidcUserInfoEndpointConfigurer authenticationProviders(
			Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
		Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
		this.authenticationProvidersConsumer = authenticationProvidersConsumer;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OidcUserInfoAuthenticationToken} and
	 * returning the {@link OidcUserInfo User Info Response}.
	 *
	 * @param userInfoResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OidcUserInfoAuthenticationToken}
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OidcUserInfoEndpointConfigurer userInfoResponseHandler(AuthenticationSuccessHandler userInfoResponseHandler) {
		this.userInfoResponseHandler = userInfoResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException} and
	 * returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OidcUserInfoEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link Function} used to extract claims from {@link OidcUserInfoAuthenticationContext}
	 * to an instance of {@link OidcUserInfo} for the UserInfo response.
	 *
	 * <p>
	 * The {@link OidcUserInfoAuthenticationContext} gives the mapper access to the {@link OidcUserInfoAuthenticationToken},
	 * as well as, the following context attributes:
	 * <ul>
	 * <li>{@link OidcUserInfoAuthenticationContext#getAccessToken()} containing the bearer token used to make the request.</li>
	 * <li>{@link OidcUserInfoAuthenticationContext#getAuthorization()} containing the {@link OidcIdToken} and
	 * {@link OAuth2AccessToken} associated with the bearer token used to make the request.</li>
	 * </ul>
	 *
	 * @param userInfoMapper the {@link Function} used to extract claims from {@link OidcUserInfoAuthenticationContext} to an instance of {@link OidcUserInfo}
	 */
	public OidcUserInfoEndpointConfigurer userInfoMapper(
			Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper) {
		this.userInfoMapper = userInfoMapper;
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		String userInfoEndpointUri = authorizationServerSettings.getOidcUserInfoEndpoint();
		this.requestMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(userInfoEndpointUri, HttpMethod.GET.name()),
				new AntPathRequestMatcher(userInfoEndpointUri, HttpMethod.POST.name()));

		List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);

		if (!this.authenticationProviders.isEmpty()) {
			authenticationProviders.addAll(0, this.authenticationProviders);
		}
		this.authenticationProvidersConsumer.accept(authenticationProviders);

		authenticationProviders.forEach(authenticationProvider ->
				httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);

		OidcUserInfoEndpointFilter oidcUserInfoEndpointFilter =
				new OidcUserInfoEndpointFilter(
						authenticationManager,
						authorizationServerSettings.getOidcUserInfoEndpoint());
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
		if (!this.userInfoRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.userInfoRequestConverters);
		}
		this.userInfoRequestConvertersConsumer.accept(authenticationConverters);
		oidcUserInfoEndpointFilter.setAuthenticationConverter(
				new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.userInfoResponseHandler != null) {
			oidcUserInfoEndpointFilter.setAuthenticationSuccessHandler(this.userInfoResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			oidcUserInfoEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		httpSecurity.addFilterAfter(postProcess(oidcUserInfoEndpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();
		authenticationConverters.add(
				(request) -> {
					Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
					return new OidcUserInfoAuthenticationToken(authentication);
				}
		);
		return authenticationConverters;
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OidcUserInfoAuthenticationProvider oidcUserInfoAuthenticationProvider = new OidcUserInfoAuthenticationProvider(
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
		if (this.userInfoMapper != null) {
			oidcUserInfoAuthenticationProvider.setUserInfoMapper(this.userInfoMapper);
		}
		authenticationProviders.add(oidcUserInfoAuthenticationProvider);

		return authenticationProviders;
	}

}
