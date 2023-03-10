/*
 * Copyright 2020-2023 the original author or authors.
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.source.JWKSource;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.NimbusJwkSetEndpointFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
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
 * @see OAuth2AuthorizationServerMetadataEndpointConfigurer
 * @see OAuth2AuthorizationEndpointConfigurer
 * @see OAuth2TokenEndpointConfigurer
 * @see OAuth2TokenIntrospectionEndpointConfigurer
 * @see OAuth2TokenRevocationEndpointConfigurer
 * @see OidcConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see NimbusJwkSetEndpointFilter
 */
public final class OAuth2AuthorizationServerConfigurer
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer, HttpSecurity> {

	private final Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = createConfigurers();
	private RequestMatcher endpointsMatcher;


	/**
	 * Sets the repository of registered clients.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer registeredClientRepository(RegisteredClientRepository registeredClientRepository) {
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
	public OAuth2AuthorizationServerConfigurer authorizationService(OAuth2AuthorizationService authorizationService) {
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
	public OAuth2AuthorizationServerConfigurer authorizationConsentService(OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		getBuilder().setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
		return this;
	}

	/**
	 * Sets the authorization server settings.
	 *
	 * @param authorizationServerSettings the authorization server settings
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer authorizationServerSettings(AuthorizationServerSettings authorizationServerSettings) {
		Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
		getBuilder().setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
		return this;
	}

	/**
	 * Sets the token generator.
	 *
	 * @param tokenGenerator the token generator
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.2.3
	 */
	public OAuth2AuthorizationServerConfigurer tokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
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
	public OAuth2AuthorizationServerConfigurer clientAuthentication(Customizer<OAuth2ClientAuthenticationConfigurer> clientAuthenticationCustomizer) {
		clientAuthenticationCustomizer.customize(getConfigurer(OAuth2ClientAuthenticationConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Authorization Server Metadata Endpoint.
	 *
	 * @param authorizationServerMetadataEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2AuthorizationServerMetadataEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 0.4.0
	 */
	public OAuth2AuthorizationServerConfigurer authorizationServerMetadataEndpoint(Customizer<OAuth2AuthorizationServerMetadataEndpointConfigurer> authorizationServerMetadataEndpointCustomizer) {
		authorizationServerMetadataEndpointCustomizer.customize(getConfigurer(OAuth2AuthorizationServerMetadataEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Authorization Endpoint.
	 *
	 * @param authorizationEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2AuthorizationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer authorizationEndpoint(Customizer<OAuth2AuthorizationEndpointConfigurer> authorizationEndpointCustomizer) {
		authorizationEndpointCustomizer.customize(getConfigurer(OAuth2AuthorizationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Token Endpoint.
	 *
	 * @param tokenEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2TokenEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer tokenEndpoint(Customizer<OAuth2TokenEndpointConfigurer> tokenEndpointCustomizer) {
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
	public OAuth2AuthorizationServerConfigurer tokenIntrospectionEndpoint(Customizer<OAuth2TokenIntrospectionEndpointConfigurer> tokenIntrospectionEndpointCustomizer) {
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
	public OAuth2AuthorizationServerConfigurer tokenRevocationEndpoint(Customizer<OAuth2TokenRevocationEndpointConfigurer> tokenRevocationEndpointCustomizer) {
		tokenRevocationEndpointCustomizer.customize(getConfigurer(OAuth2TokenRevocationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Device Authorization Endpoint.
	 *
	 * @param deviceAuthorizationEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2DeviceAuthorizationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 1.1
	 */
	public OAuth2AuthorizationServerConfigurer deviceAuthorizationEndpoint(Customizer<OAuth2DeviceAuthorizationEndpointConfigurer> deviceAuthorizationEndpointCustomizer) {
		deviceAuthorizationEndpointCustomizer.customize(getConfigurer(OAuth2DeviceAuthorizationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OAuth 2.0 Device Verification Endpoint.
	 *
	 * @param deviceVerificationEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2DeviceVerificationEndpointConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 * @since 1.1
	 */
	public OAuth2AuthorizationServerConfigurer deviceVerificationEndpoint(Customizer<OAuth2DeviceVerificationEndpointConfigurer> deviceVerificationEndpointCustomizer) {
		deviceVerificationEndpointCustomizer.customize(getConfigurer(OAuth2DeviceVerificationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures OpenID Connect 1.0 support (disabled by default).
	 *
	 * @param oidcCustomizer the {@link Customizer} providing access to the {@link OidcConfigurer}
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer oidc(Customizer<OidcConfigurer> oidcCustomizer) {
		OidcConfigurer oidcConfigurer = getConfigurer(OidcConfigurer.class);
		if (oidcConfigurer == null) {
			addConfigurer(OidcConfigurer.class, new OidcConfigurer(this::postProcess));
			oidcConfigurer = getConfigurer(OidcConfigurer.class);
		}
		oidcCustomizer.customize(oidcConfigurer);
		return this;
	}

	/**
	 * Returns a {@link RequestMatcher} for the authorization server endpoints.
	 *
	 * @return a {@link RequestMatcher} for the authorization server endpoints
	 */
	public RequestMatcher getEndpointsMatcher() {
		// Return a deferred RequestMatcher
		// since endpointsMatcher is constructed in init(HttpSecurity).
		return (request) -> this.endpointsMatcher.matches(request);
	}

	@Override
	public void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
		validateAuthorizationServerSettings(authorizationServerSettings);

		if (isOidcEnabled()) {
			// Add OpenID Connect session tracking capabilities.
			SessionRegistry sessionRegistry = OAuth2ConfigurerUtils.getSessionRegistry(httpSecurity);
			OAuth2AuthorizationEndpointConfigurer authorizationEndpointConfigurer =
					getConfigurer(OAuth2AuthorizationEndpointConfigurer.class);
			authorizationEndpointConfigurer.setSessionAuthenticationStrategy((authentication, request, response) -> {
				if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
					if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
						if (sessionRegistry.getSessionInformation(request.getSession().getId()) == null) {
							sessionRegistry.registerNewSession(
									request.getSession().getId(),
									((Authentication) authorizationCodeRequestAuthentication.getPrincipal()).getPrincipal());
						}
					}
				}
			});
		} else {
			// OpenID Connect is disabled.
			// Add an authentication validator that rejects authentication requests.
			OAuth2AuthorizationEndpointConfigurer authorizationEndpointConfigurer =
					getConfigurer(OAuth2AuthorizationEndpointConfigurer.class);
			authorizationEndpointConfigurer.addAuthorizationCodeRequestAuthenticationValidator((authenticationContext) -> {
				OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
						authenticationContext.getAuthentication();
				if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
					OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
							"OpenID Connect 1.0 authentication requests are restricted.",
							"https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1");
					throw new OAuth2AuthorizationCodeRequestAuthenticationException(
							error, authorizationCodeRequestAuthentication);
				}
			});
		}

		List<RequestMatcher> requestMatchers = new ArrayList<>();
		this.configurers.values().forEach(configurer -> {
			configurer.init(httpSecurity);
			requestMatchers.add(configurer.getRequestMatcher());
		});
		requestMatchers.add(new AntPathRequestMatcher(
				authorizationServerSettings.getJwkSetEndpoint(), HttpMethod.GET.name()));
		this.endpointsMatcher = new OrRequestMatcher(requestMatchers);

		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling = httpSecurity.getConfigurer(ExceptionHandlingConfigurer.class);
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
	public void configure(HttpSecurity httpSecurity) {
		this.configurers.values().forEach(configurer -> configurer.configure(httpSecurity));

		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);

		AuthorizationServerContextFilter authorizationServerContextFilter = new AuthorizationServerContextFilter(authorizationServerSettings);
		httpSecurity.addFilterAfter(postProcess(authorizationServerContextFilter), SecurityContextHolderFilter.class);

		JWKSource<com.nimbusds.jose.proc.SecurityContext> jwkSource = OAuth2ConfigurerUtils.getJwkSource(httpSecurity);
		if (jwkSource != null) {
			NimbusJwkSetEndpointFilter jwkSetEndpointFilter = new NimbusJwkSetEndpointFilter(
					jwkSource, authorizationServerSettings.getJwkSetEndpoint());
			httpSecurity.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
		}
	}

	private boolean isOidcEnabled() {
		return getConfigurer(OidcConfigurer.class) != null;
	}

	private Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> createConfigurers() {
		Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = new LinkedHashMap<>();
		configurers.put(OAuth2ClientAuthenticationConfigurer.class, new OAuth2ClientAuthenticationConfigurer(this::postProcess));
		configurers.put(OAuth2AuthorizationServerMetadataEndpointConfigurer.class, new OAuth2AuthorizationServerMetadataEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2AuthorizationEndpointConfigurer.class, new OAuth2AuthorizationEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2TokenEndpointConfigurer.class, new OAuth2TokenEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2TokenIntrospectionEndpointConfigurer.class, new OAuth2TokenIntrospectionEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2TokenRevocationEndpointConfigurer.class, new OAuth2TokenRevocationEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2DeviceAuthorizationEndpointConfigurer.class, new OAuth2DeviceAuthorizationEndpointConfigurer(this::postProcess));
		configurers.put(OAuth2DeviceVerificationEndpointConfigurer.class, new OAuth2DeviceVerificationEndpointConfigurer(this::postProcess));
		return configurers;
	}

	@SuppressWarnings("unchecked")
	private <T> T getConfigurer(Class<T> type) {
		return (T) this.configurers.get(type);
	}

	private <T extends AbstractOAuth2Configurer> void addConfigurer(Class<T> configurerType, T configurer) {
		this.configurers.put(configurerType, configurer);
	}

	private <T extends AbstractOAuth2Configurer> RequestMatcher getRequestMatcher(Class<T> configurerType) {
		T configurer = getConfigurer(configurerType);
		return configurer != null ? configurer.getRequestMatcher() : null;
	}

	private static void validateAuthorizationServerSettings(AuthorizationServerSettings authorizationServerSettings) {
		if (authorizationServerSettings.getIssuer() != null) {
			URI issuerUri;
			try {
				issuerUri = new URI(authorizationServerSettings.getIssuer());
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
