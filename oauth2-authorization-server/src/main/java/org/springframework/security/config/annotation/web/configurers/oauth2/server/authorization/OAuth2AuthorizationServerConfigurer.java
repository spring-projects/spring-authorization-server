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

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcClientRegistrationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcProviderConfigurationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenRevocationEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Gerardo Roza
 * @author Ovidiu Popa
 * @since 0.0.1
 * @see AbstractHttpConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see OAuth2AuthorizationEndpointFilter
 * @see OAuth2TokenEndpointFilter
 * @see OAuth2TokenIntrospectionEndpointFilter
 * @see OAuth2TokenRevocationEndpointFilter
 * @see NimbusJwkSetEndpointFilter
 * @see OidcProviderConfigurationEndpointFilter
 * @see OAuth2AuthorizationServerMetadataEndpointFilter
 * @see OAuth2ClientAuthenticationFilter
 * @see OidcClientRegistrationEndpointFilter
 */
public final class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {

	private RequestMatcher authorizationEndpointMatcher;
	private RequestMatcher tokenEndpointMatcher;
	private RequestMatcher tokenIntrospectionEndpointMatcher;
	private RequestMatcher tokenRevocationEndpointMatcher;
	private RequestMatcher jwkSetEndpointMatcher;
	private RequestMatcher oidcProviderConfigurationEndpointMatcher;
	private RequestMatcher authorizationServerMetadataEndpointMatcher;
	private RequestMatcher oidcClientRegistrationEndpointMatcher;
	private final RequestMatcher endpointsMatcher = (request) ->
			this.authorizationEndpointMatcher.matches(request) ||
			this.tokenEndpointMatcher.matches(request) ||
			this.tokenIntrospectionEndpointMatcher.matches(request) ||
			this.tokenRevocationEndpointMatcher.matches(request) ||
			this.jwkSetEndpointMatcher.matches(request) ||
			this.oidcProviderConfigurationEndpointMatcher.matches(request) ||
			this.authorizationServerMetadataEndpointMatcher.matches(request) ||
			this.oidcClientRegistrationEndpointMatcher.matches(request);
	private String consentPage;

	/**
	 * Sets the repository of registered clients.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> registeredClientRepository(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.getBuilder().setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
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
		this.getBuilder().setSharedObject(OAuth2AuthorizationService.class, authorizationService);
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
		this.getBuilder().setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
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
		this.getBuilder().setSharedObject(ProviderSettings.class, providerSettings);
		return this;
	}

	/**
	 * Specify the URI to redirect Resource Owners to if consent is required during
	 * the {@code authorization_code} flow. A default consent page will be generated when
	 * this attribute is not specified.
	 *
	 * If a URI is specified, applications are required to process the specified URI to generate
	 * a consent page. The query string will contain the following parameters:
	 *
	 * <ul>
	 * <li>{@code client_id} - the client identifier</li>
	 * <li>{@code scope} - the space separated list of scopes present in the authorization request</li>
	 * <li>{@code state} - a CSRF protection token</li>
	 * </ul>
	 *
	 * In general, the consent page should create a form that submits
	 * a request with the following requirements:
	 *
	 * <ul>
	 * <li>It must be an HTTP POST</li>
	 * <li>It must be submitted to {@link ProviderSettings#authorizationEndpoint()}</li>
	 * <li>It must include the received {@code client_id} as an HTTP parameter</li>
	 * <li>It must include the received {@code state} as an HTTP parameter</li>
	 * <li>It must include the list of {@code scope}s the {@code Resource Owner}
	 * consented to as an HTTP parameter</li>
	 * <li>It must include the {@code consent_action} parameter, with a value either
	 * {@code approve} or {@code cancel} as an HTTP parameter</li>
	 * </ul>
	 *
	 * @param consentPage the consent page to redirect to if consent is required (e.g. "/oauth2/consent")
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> consentPage(String consentPage) {
		this.consentPage = consentPage;
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

		OAuth2ClientAuthenticationProvider clientAuthenticationProvider =
				new OAuth2ClientAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
						OAuth2ConfigurerUtils.getAuthorizationService(builder));
		PasswordEncoder passwordEncoder = OAuth2ConfigurerUtils.getOptionalBean(builder, PasswordEncoder.class);
		if (passwordEncoder != null) {
			clientAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		}
		builder.authenticationProvider(postProcess(clientAuthenticationProvider));

		JwtEncoder jwtEncoder = OAuth2ConfigurerUtils.getJwtEncoder(builder);
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = OAuth2ConfigurerUtils.getJwtCustomizer(builder);

		OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
				new OAuth2AuthorizationCodeAuthenticationProvider(
						OAuth2ConfigurerUtils.getAuthorizationService(builder),
						jwtEncoder);
		if (jwtCustomizer != null) {
			authorizationCodeAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
		}
		builder.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));

		OAuth2RefreshTokenAuthenticationProvider refreshTokenAuthenticationProvider =
				new OAuth2RefreshTokenAuthenticationProvider(
						OAuth2ConfigurerUtils.getAuthorizationService(builder),
						jwtEncoder);
		if (jwtCustomizer != null) {
			refreshTokenAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
		}
		builder.authenticationProvider(postProcess(refreshTokenAuthenticationProvider));

		OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider =
				new OAuth2ClientCredentialsAuthenticationProvider(
						OAuth2ConfigurerUtils.getAuthorizationService(builder),
						jwtEncoder);
		if (jwtCustomizer != null) {
			clientCredentialsAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
		}
		builder.authenticationProvider(postProcess(clientCredentialsAuthenticationProvider));

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
							this.tokenEndpointMatcher,
							this.tokenIntrospectionEndpointMatcher,
							this.tokenRevocationEndpointMatcher)
			);
		}
	}

	@Override
	public void configure(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		if (providerSettings.issuer() != null) {
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
				providerSettings.jwkSetEndpoint());
		builder.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

		OAuth2ClientAuthenticationFilter clientAuthenticationFilter =
				new OAuth2ClientAuthenticationFilter(
						authenticationManager,
						new OrRequestMatcher(
								this.tokenEndpointMatcher,
								this.tokenIntrospectionEndpointMatcher,
								this.tokenRevocationEndpointMatcher));
		builder.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);

		OAuth2AuthorizationEndpointFilter authorizationEndpointFilter =
				new OAuth2AuthorizationEndpointFilter(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
						OAuth2ConfigurerUtils.getAuthorizationService(builder),
						OAuth2ConfigurerUtils.getAuthorizationConsentService(builder),
						providerSettings.authorizationEndpoint());
		if (StringUtils.hasText(this.consentPage)) {
			authorizationEndpointFilter.setUserConsentUri(this.consentPage);
		}
		builder.addFilterBefore(postProcess(authorizationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		OAuth2TokenEndpointFilter tokenEndpointFilter =
				new OAuth2TokenEndpointFilter(
						authenticationManager,
						providerSettings.tokenEndpoint());
		builder.addFilterAfter(postProcess(tokenEndpointFilter), FilterSecurityInterceptor.class);

		OAuth2TokenIntrospectionEndpointFilter tokenIntrospectionEndpointFilter =
				new OAuth2TokenIntrospectionEndpointFilter(
						authenticationManager,
						providerSettings.tokenIntrospectionEndpoint());
		builder.addFilterAfter(postProcess(tokenIntrospectionEndpointFilter), OAuth2TokenEndpointFilter.class);

		OAuth2TokenRevocationEndpointFilter tokenRevocationEndpointFilter =
				new OAuth2TokenRevocationEndpointFilter(
						authenticationManager,
						providerSettings.tokenRevocationEndpoint());
		builder.addFilterAfter(postProcess(tokenRevocationEndpointFilter), OAuth2TokenIntrospectionEndpointFilter.class);

		// TODO Make OpenID Client Registration an "opt-in" feature
		OidcClientRegistrationEndpointFilter oidcClientRegistrationEndpointFilter =
				new OidcClientRegistrationEndpointFilter(
						authenticationManager,
						providerSettings.oidcClientRegistrationEndpoint());
		builder.addFilterAfter(postProcess(oidcClientRegistrationEndpointFilter), OAuth2TokenRevocationEndpointFilter.class);
	}

	private void initEndpointMatchers(ProviderSettings providerSettings) {
		this.authorizationEndpointMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(
						providerSettings.authorizationEndpoint(),
						HttpMethod.GET.name()),
				new AntPathRequestMatcher(
						providerSettings.authorizationEndpoint(),
						HttpMethod.POST.name()));
		this.tokenEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.tokenEndpoint(), HttpMethod.POST.name());
		this.tokenIntrospectionEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.tokenIntrospectionEndpoint(), HttpMethod.POST.name());
		this.tokenRevocationEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.tokenRevocationEndpoint(), HttpMethod.POST.name());
		this.jwkSetEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.jwkSetEndpoint(), HttpMethod.GET.name());
		this.oidcProviderConfigurationEndpointMatcher = new AntPathRequestMatcher(
				OidcProviderConfigurationEndpointFilter.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI, HttpMethod.GET.name());
		this.authorizationServerMetadataEndpointMatcher = new AntPathRequestMatcher(
				OAuth2AuthorizationServerMetadataEndpointFilter.DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI, HttpMethod.GET.name());
		this.oidcClientRegistrationEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.oidcClientRegistrationEndpoint(), HttpMethod.POST.name());
	}

	private static void validateProviderSettings(ProviderSettings providerSettings) {
		if (providerSettings.issuer() != null) {
			try {
				new URI(providerSettings.issuer()).toURL();
			} catch (Exception ex) {
				throw new IllegalArgumentException("issuer must be a valid URL", ex);
			}
		}
	}

}
