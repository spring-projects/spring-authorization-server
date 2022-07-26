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

import java.util.function.Function;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Configurer for OpenID Connect 1.0 UserInfo Endpoint.
 *
 * @author Steve Riesenberg
 * @since 0.2.1
 * @see OidcConfigurer#userInfoEndpoint
 * @see OidcUserInfoEndpointFilter
 */
public final class OidcUserInfoEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper;

	/**
	 * Restrict for internal use only.
	 */
	OidcUserInfoEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
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
	 * @return the {@link OidcUserInfoEndpointConfigurer} for further configuration
	 */
	public OidcUserInfoEndpointConfigurer userInfoMapper(Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper) {
		this.userInfoMapper = userInfoMapper;
		return this;
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		String userInfoEndpointUri = providerSettings.getOidcUserInfoEndpoint();
		this.requestMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(userInfoEndpointUri, HttpMethod.GET.name()),
				new AntPathRequestMatcher(userInfoEndpointUri, HttpMethod.POST.name()));

		OidcUserInfoAuthenticationProvider oidcUserInfoAuthenticationProvider =
				new OidcUserInfoAuthenticationProvider(
						OAuth2ConfigurerUtils.getAuthorizationService(builder));
		if (this.userInfoMapper != null) {
			oidcUserInfoAuthenticationProvider.setUserInfoMapper(this.userInfoMapper);
		}
		builder.authenticationProvider(postProcess(oidcUserInfoAuthenticationProvider));
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);

		OidcUserInfoEndpointFilter oidcUserInfoEndpointFilter =
				new OidcUserInfoEndpointFilter(
						authenticationManager,
						providerSettings.getOidcUserInfoEndpoint());
		builder.addFilterAfter(postProcess(oidcUserInfoEndpointFilter), FilterSecurityInterceptor.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

}
