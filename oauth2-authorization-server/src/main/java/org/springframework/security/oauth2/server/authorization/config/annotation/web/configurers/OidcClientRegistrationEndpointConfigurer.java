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

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcClientRegistrationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Configurer for OpenID Connect Dynamic Client Registration 1.0 Endpoint.
 *
 * @author Joe Grandja
 * @since 0.2.0
 * @see OidcConfigurer#clientRegistrationEndpoint
 * @see OidcClientRegistrationEndpointFilter
 */
public final class OidcClientRegistrationEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;

	/**
	 * Restrict for internal use only.
	 */
	OidcClientRegistrationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		this.requestMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(authorizationServerSettings.getOidcClientRegistrationEndpoint(), HttpMethod.POST.name()),
				new AntPathRequestMatcher(authorizationServerSettings.getOidcClientRegistrationEndpoint(), HttpMethod.GET.name())
		);

		OidcClientRegistrationAuthenticationProvider oidcClientRegistrationAuthenticationProvider =
				new OidcClientRegistrationAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
						OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity),
						OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity));
		httpSecurity.authenticationProvider(postProcess(oidcClientRegistrationAuthenticationProvider));
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);

		OidcClientRegistrationEndpointFilter oidcClientRegistrationEndpointFilter =
				new OidcClientRegistrationEndpointFilter(
						authenticationManager,
						authorizationServerSettings.getOidcClientRegistrationEndpoint());
		httpSecurity.addFilterAfter(postProcess(oidcClientRegistrationEndpointFilter), AuthorizationFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

}
