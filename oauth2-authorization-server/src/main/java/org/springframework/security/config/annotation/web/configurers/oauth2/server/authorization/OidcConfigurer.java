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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcClientRegistrationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
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
 * @see OidcProviderConfigurationEndpointFilter
 * @see OidcClientRegistrationEndpointFilter
 */
public final class OidcConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;

	/**
	 * Restrict for internal use only.
	 */
	OidcConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		List<RequestMatcher> requestMatchers = new ArrayList<>();
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		if (providerSettings.getIssuer() != null) {
			requestMatchers.add(
					new AntPathRequestMatcher(
							"/.well-known/openid-configuration",
							HttpMethod.GET.name()));
		}
		requestMatchers.add(
				new AntPathRequestMatcher(
						providerSettings.getOidcClientRegistrationEndpoint(),
						HttpMethod.POST.name()));
		this.requestMatcher = new OrRequestMatcher(requestMatchers);

		// TODO Make OpenID Client Registration an "opt-in" feature
		OidcClientRegistrationAuthenticationProvider oidcClientRegistrationAuthenticationProvider =
				new OidcClientRegistrationAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
						OAuth2ConfigurerUtils.getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(oidcClientRegistrationAuthenticationProvider));
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		if (providerSettings.getIssuer() != null) {
			OidcProviderConfigurationEndpointFilter oidcProviderConfigurationEndpointFilter =
					new OidcProviderConfigurationEndpointFilter(providerSettings);
			builder.addFilterBefore(postProcess(oidcProviderConfigurationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
		}

		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

		// TODO Make OpenID Client Registration an "opt-in" feature
		OidcClientRegistrationEndpointFilter oidcClientRegistrationEndpointFilter =
				new OidcClientRegistrationEndpointFilter(
						authenticationManager,
						providerSettings.getOidcClientRegistrationEndpoint());
		builder.addFilterAfter(postProcess(oidcClientRegistrationEndpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

}
