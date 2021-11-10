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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
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
	private final OidcUserInfoEndpointConfigurer userInfoEndpointConfigurer;
	private OidcClientRegistrationEndpointConfigurer clientRegistrationEndpointConfigurer;
	private RequestMatcher requestMatcher;

	/**
	 * Restrict for internal use only.
	 */
	OidcConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
		this.userInfoEndpointConfigurer = new OidcUserInfoEndpointConfigurer(objectPostProcessor);
	}

	/**
	 * Configures the OpenID Connect Dynamic Client Registration 1.0 Endpoint.
	 *
	 * @param clientRegistrationEndpointCustomizer the {@link Customizer} providing access to the {@link OidcClientRegistrationEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer clientRegistrationEndpoint(Customizer<OidcClientRegistrationEndpointConfigurer> clientRegistrationEndpointCustomizer) {
		if (this.clientRegistrationEndpointConfigurer == null) {
			this.clientRegistrationEndpointConfigurer = new OidcClientRegistrationEndpointConfigurer(getObjectPostProcessor());
		}
		clientRegistrationEndpointCustomizer.customize(this.clientRegistrationEndpointConfigurer);
		return this;
	}

	/**
	 * Configures the OpenID Connect 1.0 UserInfo Endpoint.
	 *
	 * @param userInfoEndpointCustomizer the {@link Customizer} providing access to the {@link OidcUserInfoEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer userInfoEndpoint(Customizer<OidcUserInfoEndpointConfigurer> userInfoEndpointCustomizer) {
		userInfoEndpointCustomizer.customize(this.userInfoEndpointConfigurer);
		return this;
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		this.userInfoEndpointConfigurer.init(builder);
		if (this.clientRegistrationEndpointConfigurer != null) {
			this.clientRegistrationEndpointConfigurer.init(builder);
		}

		List<RequestMatcher> requestMatchers = new ArrayList<>();
		requestMatchers.add(new AntPathRequestMatcher(
				"/.well-known/openid-configuration", HttpMethod.GET.name()));
		requestMatchers.add(this.userInfoEndpointConfigurer.getRequestMatcher());
		if (this.clientRegistrationEndpointConfigurer != null) {
			requestMatchers.add(this.clientRegistrationEndpointConfigurer.getRequestMatcher());
		}
		this.requestMatcher = new OrRequestMatcher(requestMatchers);
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		this.userInfoEndpointConfigurer.configure(builder);
		if (this.clientRegistrationEndpointConfigurer != null) {
			this.clientRegistrationEndpointConfigurer.configure(builder);
		}

		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		OidcProviderConfigurationEndpointFilter oidcProviderConfigurationEndpointFilter =
				new OidcProviderConfigurationEndpointFilter(providerSettings);
		builder.addFilterBefore(postProcess(oidcProviderConfigurationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

}
