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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Configurer for OpenID Connect 1.0 support.
 *
 * @author Joe Grandja
 * @since 0.2.0
 * @see OAuth2AuthorizationServerConfigurer#oidc
 * @see OidcClientRegistrationEndpointConfigurer
 * @see OidcUserInfoEndpointConfigurer
 * @see OidcProviderConfigurationEndpointFilter
 */
public final class OidcConfigurer extends AbstractOAuth2Configurer {
	private final Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = new LinkedHashMap<>();
	private RequestMatcher requestMatcher;

	/**
	 * Restrict for internal use only.
	 */
	OidcConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
		addConfigurer(OidcUserInfoEndpointConfigurer.class, new OidcUserInfoEndpointConfigurer(objectPostProcessor));
	}

	/**
	 * Configures the OpenID Connect Dynamic Client Registration 1.0 Endpoint.
	 *
	 * @param clientRegistrationEndpointCustomizer the {@link Customizer} providing access to the {@link OidcClientRegistrationEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer clientRegistrationEndpoint(Customizer<OidcClientRegistrationEndpointConfigurer> clientRegistrationEndpointCustomizer) {
		OidcClientRegistrationEndpointConfigurer clientRegistrationEndpointConfigurer =
				getConfigurer(OidcClientRegistrationEndpointConfigurer.class);
		if (clientRegistrationEndpointConfigurer == null) {
			addConfigurer(OidcClientRegistrationEndpointConfigurer.class,
					new OidcClientRegistrationEndpointConfigurer(getObjectPostProcessor()));
			clientRegistrationEndpointConfigurer = getConfigurer(OidcClientRegistrationEndpointConfigurer.class);
		}
		clientRegistrationEndpointCustomizer.customize(clientRegistrationEndpointConfigurer);
		return this;
	}

	/**
	 * Configures the OpenID Connect 1.0 UserInfo Endpoint.
	 *
	 * @param userInfoEndpointCustomizer the {@link Customizer} providing access to the {@link OidcUserInfoEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer userInfoEndpoint(Customizer<OidcUserInfoEndpointConfigurer> userInfoEndpointCustomizer) {
		userInfoEndpointCustomizer.customize(getConfigurer(OidcUserInfoEndpointConfigurer.class));
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		OidcUserInfoEndpointConfigurer userInfoEndpointConfigurer =
				getConfigurer(OidcUserInfoEndpointConfigurer.class);
		userInfoEndpointConfigurer.init(httpSecurity);
		OidcClientRegistrationEndpointConfigurer clientRegistrationEndpointConfigurer =
				getConfigurer(OidcClientRegistrationEndpointConfigurer.class);
		if (clientRegistrationEndpointConfigurer != null) {
			clientRegistrationEndpointConfigurer.init(httpSecurity);
		}

		List<RequestMatcher> requestMatchers = new ArrayList<>();
		requestMatchers.add(new AntPathRequestMatcher(
				"/.well-known/openid-configuration", HttpMethod.GET.name()));
		requestMatchers.add(userInfoEndpointConfigurer.getRequestMatcher());
		if (clientRegistrationEndpointConfigurer != null) {
			requestMatchers.add(clientRegistrationEndpointConfigurer.getRequestMatcher());
		}
		this.requestMatcher = new OrRequestMatcher(requestMatchers);
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		OidcUserInfoEndpointConfigurer userInfoEndpointConfigurer =
				getConfigurer(OidcUserInfoEndpointConfigurer.class);
		userInfoEndpointConfigurer.configure(httpSecurity);
		OidcClientRegistrationEndpointConfigurer clientRegistrationEndpointConfigurer =
				getConfigurer(OidcClientRegistrationEndpointConfigurer.class);
		if (clientRegistrationEndpointConfigurer != null) {
			clientRegistrationEndpointConfigurer.configure(httpSecurity);
		}

		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		OidcProviderConfigurationEndpointFilter oidcProviderConfigurationEndpointFilter =
				new OidcProviderConfigurationEndpointFilter(authorizationServerSettings);
		httpSecurity.addFilterBefore(postProcess(oidcProviderConfigurationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	@SuppressWarnings("unchecked")
	<T> T getConfigurer(Class<T> type) {
		return (T) this.configurers.get(type);
	}

	private <T extends AbstractOAuth2Configurer> void addConfigurer(Class<T> configurerType, T configurer) {
		this.configurers.put(configurerType, configurer);
	}

}
