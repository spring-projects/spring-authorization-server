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

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.jwk.source.JWKSource;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.ProviderContextFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
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
 * @author Gaurav Tiwari
 * @since 0.0.1
 * @see AbstractHttpConfigurer
 * @see OAuth2ClientAuthenticationConfigurer
 * @see OAuth2AuthorizationEndpointConfigurer
 * @see OAuth2TokenEndpointConfigurer
 * @see OAuth2TokenIntrospectionEndpointConfigurer
 * @see OAuth2TokenRevocationEndpointConfigurer
 * @see OidcConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see NimbusJwkSetEndpointFilter
 * @see OAuth2AuthorizationServerMetadataEndpointFilter
 */
public final class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {

	private final Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = createConfigurers();
	private RequestMatcher jwkSetEndpointMatcher;
	private RequestMatcher authorizationServerMetadataEndpointMatcher;
	private final RequestMatcher endpointsMatcher = (request) ->
			getRequestMatcher(OAuth2AuthorizationEndpointConfigurer.class).matches(request) ||
			getRequestMatcher(OAuth2TokenEndpointConfigurer.class).matches(request) ||
			getRequestMatcher(OAuth2TokenIntrospectionEndpointConfigurer.class).matches(request) ||
			getRequestMatcher(OAuth2TokenRevocationEndpointConfigurer.class).matches(request) ||
			getRequestMatcher(OidcConfigurer.class).matches(request) ||
			this.jwkSetEndpointMatcher.matches(request) ||
			this.authorizationServerMetadataEndpointMatcher.matches(request);

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
	 * Sets the token generator.
	 *
	 * @param tokenGenerator the token generator
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.2.3
	 */
	public OAuth2AuthorizationServerConfigurer<B> tokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		getBuilder().setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
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
	 * Configures the OAuth 2.0 Token Introspection Endpoint.
	 *
	 * @param tokenIntrospectionEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2TokenIntrospectionEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.2.3
	 */
	public OAuth2AuthorizationServerConfigurer<B> tokenIntrospectionEndpoint(Customizer<OAuth2TokenIntrospectionEndpointConfigurer> tokenIntrospectionEndpointCustomizer) {
		tokenIntrospectionEndpointCustomizer.customize(getConfigurer(OAuth2TokenIntrospectionEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Token Revocation Endpoint.
	 *
	 * @param tokenRevocationEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2TokenRevocationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.2.2
	 */
	public OAuth2AuthorizationServerConfigurer<B> tokenRevocationEndpoint(Customizer<OAuth2TokenRevocationEndpointConfigurer> tokenRevocationEndpointCustomizer) {
		tokenRevocationEndpointCustomizer.customize(getConfigurer(OAuth2TokenRevocationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures OpenID Connect 1.0 support.
	 *
	 * @param oidcCustomizer the {@link Customizer} providing access to the {@link OidcConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> oidc(Customizer<OidcConfigurer> oidcCustomizer) {
		oidcCustomizer.customize(getConfigurer(OidcConfigurer.class));
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

		ExceptionHandlingConfigurer<B> exceptionHandling = builder.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			exceptionHandling.defaultAuthenticationEntryPointFor(
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
					new OrRequestMatcher(
							getRequestMatcher(OAuth2TokenEndpointConfigurer.class),
							getRequestMatcher(OAuth2TokenIntrospectionEndpointConfigurer.class),
							getRequestMatcher(OAuth2TokenRevocationEndpointConfigurer.class))
			);
		}
	}

	@Override
	public void configure(B builder) {
		this.configurers.values().forEach(configurer -> configurer.configure(builder));

		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);

		ProviderContextFilter providerContextFilter = new ProviderContextFilter(providerSettings);
		builder.addFilterAfter(postProcess(providerContextFilter), SecurityContextPersistenceFilter.class);

		JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource = OAuth2ConfigurerUtils.getJwkSource(builder);
		if (jwkSource != null) {
			NimbusJwkSetEndpointFilter jwkSetEndpointFilter = new NimbusJwkSetEndpointFilter(
					jwkSource, providerSettings.getJwkSetEndpoint());
			builder.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
		}

		OAuth2AuthorizationServerMetadataEndpointFilter authorizationServerMetadataEndpointFilter =
				new OAuth2AuthorizationServerMetadataEndpointFilter(providerSettings);
		builder.addFilterBefore(postProcess(authorizationServerMetadataEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
	}

	private Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> createConfigurers() {
		Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = new LinkedHashMap<>();
		configurers.put(OAuth2ClientAuthenticationConfigurer.class, new OAuth2ClientAuthenticationConfigurer(this::postProcess));
		configurers.put(OAuth2AuthorizationEndpointConfigurer.class, new OAuth2AuthorizationEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2TokenEndpointConfigurer.class, new OAuth2TokenEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2TokenIntrospectionEndpointConfigurer.class, new OAuth2TokenIntrospectionEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2TokenRevocationEndpointConfigurer.class, new OAuth2TokenRevocationEndpointConfigurer(this::postProcess));
		configurers.put(OidcConfigurer.class, new OidcConfigurer(this::postProcess));
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
		this.jwkSetEndpointMatcher = new AntPathRequestMatcher(
				providerSettings.getJwkSetEndpoint(), HttpMethod.GET.name());
		this.authorizationServerMetadataEndpointMatcher = new AntPathRequestMatcher(
				"/.well-known/oauth-authorization-server", HttpMethod.GET.name());
	}

	private static void validateProviderSettings(ProviderSettings providerSettings) {
		if (providerSettings.getIssuer() != null) {
			URI issuerUri;
			try {
				issuerUri = new URI(providerSettings.getIssuer());
				issuerUri.toURL();
			} catch (Exception ex) {
				throw new IllegalArgumentException("issuer must be a valid URL", ex);
			}
			// rfc8414 https://datatracker.ietf.org/doc/html/rfc8414#section-2
			if (issuerUri.getQuery() != null || issuerUri.getFragment() != null) {
				throw new IllegalArgumentException("issuer cannot contain query or fragment component");
			}
		}
	}

}
