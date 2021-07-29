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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcClientRegistrationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Gerardo Roza
 * @author Ovidiu Popa
 * @since 0.0.1
 * @see AbstractHttpConfigurer
 * @see OAuth2ClientAuthenticationConfigurer
 * @see OAuth2AuthorizationEndpointConfigurer
 * @see OAuth2TokenEndpointConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see OAuth2TokenIntrospectionEndpointFilter
 * @see OAuth2TokenRevocationEndpointFilter
 * @see NimbusJwkSetEndpointFilter
 * @see OidcProviderConfigurationEndpointFilter
 * @see OAuth2AuthorizationServerMetadataEndpointFilter
 * @see OidcClientRegistrationEndpointFilter
 */
public final class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {

	private final Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = createConfigurers();
	private RequestMatcher tokenIntrospectionEndpointMatcher;
	private RequestMatcher tokenRevocationEndpointMatcher;
	private RequestMatcher jwkSetEndpointMatcher;
	private RequestMatcher oidcProviderConfigurationEndpointMatcher;
	private RequestMatcher authorizationServerMetadataEndpointMatcher;
	private RequestMatcher oidcClientRegistrationEndpointMatcher;
	private final RequestMatcher endpointsMatcher = (request) ->
			getRequestMatcher(OAuth2AuthorizationEndpointConfigurer.class).matches(request) ||
			getRequestMatcher(OAuth2TokenEndpointConfigurer.class).matches(request) ||
			this.tokenIntrospectionEndpointMatcher.matches(request) ||
			this.tokenRevocationEndpointMatcher.matches(request) ||
			this.jwkSetEndpointMatcher.matches(request) ||
			this.oidcProviderConfigurationEndpointMatcher.matches(request) ||
			this.authorizationServerMetadataEndpointMatcher.matches(request) ||
			this.oidcClientRegistrationEndpointMatcher.matches(request);

	/**
	 * Sets the repository of registered clients.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> registeredClientRepository(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		getBuilder().setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		return this;
	}

	/**
	 * Sets the authorization service.
	 *
	 * @param authorizationService the authorization service
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> authorizationService(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		getBuilder().setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		return this;
	}

	/**
	 * Sets the authorization consent service.
	 *
	 * @param authorizationConsentService the authorization consent service
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> authorizationConsentService(OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		getBuilder().setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
		return this;
	}

	/**
	 * Sets the provider settings.
	 *
	 * @param providerSettings the provider settings
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> providerSettings(ProviderSettings providerSettings) {
		Assert.notNull(providerSettings, "providerSettings cannot be null");
		getBuilder().setSharedObject(ProviderSettings.class, providerSettings);
		return this;
	}

	/**
	 * Configures OAuth 2.0 Client Authentication.
	 *
	 * @param clientAuthenticationCustomizer the {@link Customizer} providing access to the {@link OAuth2ClientAuthenticationConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> clientAuthentication(Customizer<OAuth2ClientAuthenticationConfigurer> clientAuthenticationCustomizer) {
		clientAuthenticationCustomizer.customize(getConfigurer(OAuth2ClientAuthenticationConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Authorization Endpoint.
	 *
	 * @param authorizationEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2AuthorizationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> authorizationEndpoint(Customizer<OAuth2AuthorizationEndpointConfigurer> authorizationEndpointCustomizer) {
		authorizationEndpointCustomizer.customize(getConfigurer(OAuth2AuthorizationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Token Endpoint.
	 *
	 * @param tokenEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2TokenEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> tokenEndpoint(Customizer<OAuth2TokenEndpointConfigurer> tokenEndpointCustomizer) {
		tokenEndpointCustomizer.customize(getConfigurer(OAuth2TokenEndpointConfigurer.class));
		return this;
	}

	/**
	 * Returns a {@link RequestMatcher} for the authorization server endpoints.
	 *
	 * @return a {@link RequestMatcher} for the authorization server endpoints
	 */
	public RequestMatcher getEndpointsMatcher() {
		return this.endpointsMatcher;
	}

	@Override
	public void init(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		validateProviderSettings(providerSettings);
		initEndpointMatchers(providerSettings);

		this.configurers.values().forEach(configurer -> configurer.init(builder));

		OAuth2TokenIntrospectionAuthenticationProvider tokenIntrospectionAuthenticationProvider =
				new OAuth2TokenIntrospectionAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
						OAuth2ConfigurerUtils.getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(tokenIntrospectionAuthenticationProvider));

		OAuth2TokenRevocationAuthenticationProvider tokenRevocationAuthenticationProvider =
				new OAuth2TokenRevocationAuthenticationProvider(
						OAuth2ConfigurerUtils.getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(tokenRevocationAuthenticationProvider));

		// TODO Make OpenID Client Registration an "opt-in" feature
		OidcClientRegistrationAuthenticationProvider oidcClientRegistrationAuthenticationProvider =
				new OidcClientRegistrationAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
						OAuth2ConfigurerUtils.getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(oidcClientRegistrationAuthenticationProvider));

		ExceptionHandlingConfigurer<B> exceptionHandling = builder.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			exceptionHandling.defaultAuthenticationEntryPointFor(
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
					new OrRequestMatcher(
							getRequestMatcher(OAuth2TokenEndpointConfigurer.class),
							this.tokenIntrospectionEndpointMatcher,
							this.tokenRevocationEndpointMatcher)
			);
		}
	}

	@Override
	public void configure(B builder) {
		this.configurers.values().forEach(configurer -> configurer.configure(builder));

		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		if (providerSettings.getIssuer() != null) {
			OidcProviderConfigurationEndpointFilter oidcProviderConfigurationEndpointFilter =
					new OidcProviderConfigurationEndpointFilter(providerSettings);
			builder.addFilterBefore(postProcess(oidcProviderConfigurationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

			OAuth2AuthorizationServerMetadataEndpointFilter authorizationServerMetadataEndpointFilter =
					new OAuth2AuthorizationServerMetadataEndpointFilter(providerSettings);
			builder.addFilterBefore(postProcess(authorizationServerMetadataEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
		}

		JWKSource<SecurityContext> jwkSource = OAuth2ConfigurerUtils.getJwkSource(builder);
		NimbusJwkSetEndpointFilter jwkSetEndpointFilter = new NimbusJwkSetEndpointFilter(
				jwkSource,
				providerSettings.getJwkSetEndpoint());
		builder.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

		OAuth2TokenIntrospectionEndpointFilter tokenIntrospectionEndpointFilter =
				new OAuth2TokenIntrospectionEndpointFilter(
						authenticationManager,
						providerSettings.getTokenIntrospectionEndpoint());
		builder.addFilterAfter(postProcess(tokenIntrospectionEndpointFilter), FilterSecurityInterceptor.class);

		OAuth2TokenRevocationEndpointFilter tokenRevocationEndpointFilter =
				new OAuth2TokenRevocationEndpointFilter(
						authenticationManager,
						providerSettings.getTokenRevocationEndpoint());
		builder.addFilterAfter(postProcess(tokenRevocationEndpointFilter), OAuth2TokenIntrospectionEndpointFilter.class);

		// TODO Make OpenID Client Registration an "opt-in" feature
		OidcClientRegistrationEndpointFilter oidcClientRegistrationEndpointFilter =
				new OidcClientRegistrationEndpointFilter(
						authenticationManager,
						providerSettings.getOidcClientRegistrationEndpoint());
		builder.addFilterAfter(postProcess(oidcClientRegistrationEndpointFilter), OAuth2TokenRevocationEndpointFilter.class);
	}

	private Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> createConfigurers() {
		Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = new LinkedHashMap<>();
		configurers.put(OAuth2ClientAuthenticationConfigurer.class, new OAuth2ClientAuthenticationConfigurer(this::postProcess));
		configurers.put(OAuth2AuthorizationEndpointConfigurer.class, new OAuth2AuthorizationEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2TokenEndpointConfigurer.class, new OAuth2TokenEndpointConfigurer(this::postProcess));
		return configurers;
	}

	@SuppressWarnings("unchecked")
	private <T> T getConfigurer(Class<T> type) {
		return (T) this.configurers.get(type);
	}

	private <T extends AbstractOAuth2Configurer> RequestMatcher getRequestMatcher(Class<T> configurerType) {
		return getConfigurer(configurerType).getRequestMatcher();
	}

	private void initEndpointMatchers(ProviderSettings providerSettings) {
		this.tokenIntrospectionEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.getTokenIntrospectionEndpoint(), HttpMethod.POST.name());
		this.tokenRevocationEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.getTokenRevocationEndpoint(), HttpMethod.POST.name());
		this.jwkSetEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.getJwkSetEndpoint(), HttpMethod.GET.name());
		this.oidcProviderConfigurationEndpointMatcher = new AntPathRequestMatcher(
				"/.well-known/openid-configuration", HttpMethod.GET.name());
		this.authorizationServerMetadataEndpointMatcher = new AntPathRequestMatcher(
				"/.well-known/oauth-authorization-server", HttpMethod.GET.name());
		this.oidcClientRegistrationEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.getOidcClientRegistrationEndpoint(), HttpMethod.POST.name());
	}

	private static void validateProviderSettings(ProviderSettings providerSettings) {
		if (providerSettings.getIssuer() != null) {
			try {
				new URI(providerSettings.getIssuer()).toURL();
			} catch (Exception ex) {
				throw new IllegalArgumentException("issuer must be a valid URL", ex);
			}
		}
	}

}
