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

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Configurer for the OAuth 2.0 Authorization Endpoint.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see OAuth2AuthorizationServerConfigurer#authorizationEndpoint
 * @see OAuth2AuthorizationEndpointFilter
 */
public final class OAuth2AuthorizationEndpointConfigurer extends AbstractOAuth2Configurer {
	private RequestMatcher requestMatcher;
	private AuthenticationConverter authorizationRequestConverter;
	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
	private AuthenticationSuccessHandler authorizationResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;
	private String consentPage;

	/**
	 * Restrict for internal use only.
	 */
	OAuth2AuthorizationEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} used for authenticating the request.
	 *
	 * @param authorizationRequestConverter the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authorizationRequestConverter(AuthenticationConverter authorizationRequestConverter) {
		this.authorizationRequestConverter = authorizationRequestConverter;
		return this;
	}

	/**
	 * Adds an {@link AuthenticationProvider} used for authenticating an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
	 *
	 * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		this.authenticationProviders.add(authenticationProvider);
		return this;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * and returning the {@link OAuth2AuthorizationResponse Authorization Response}.
	 *
	 * @param authorizationResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer authorizationResponseHandler(AuthenticationSuccessHandler authorizationResponseHandler) {
		this.authorizationResponseHandler = authorizationResponseHandler;
		return this;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
		this.errorResponseHandler = errorResponseHandler;
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
	 * <li>{@code scope} - a space-delimited list of scopes present in the authorization request</li>
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
	 * </ul>
	 *
	 * @param consentPage the URI of the custom consent page to redirect to if consent is required (e.g. "/oauth2/consent")
	 * @return the {@link OAuth2AuthorizationEndpointConfigurer} for further configuration
	 */
	public OAuth2AuthorizationEndpointConfigurer consentPage(String consentPage) {
		this.consentPage = consentPage;
		return this;
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void init(B builder) {
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
		this.requestMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(
						providerSettings.authorizationEndpoint(),
						HttpMethod.GET.name()),
				new AntPathRequestMatcher(
						providerSettings.authorizationEndpoint(),
						HttpMethod.POST.name()));

		List<AuthenticationProvider> authenticationProviders =
				!this.authenticationProviders.isEmpty() ?
						this.authenticationProviders :
						createDefaultAuthenticationProviders(builder);
		authenticationProviders.forEach(authenticationProvider ->
				builder.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	<B extends HttpSecurityBuilder<B>> void configure(B builder) {
		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
		ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);

		OAuth2AuthorizationEndpointFilter authorizationEndpointFilter =
				new OAuth2AuthorizationEndpointFilter(
						authenticationManager,
						providerSettings.authorizationEndpoint());
		if (this.authorizationRequestConverter != null) {
			authorizationEndpointFilter.setAuthenticationConverter(this.authorizationRequestConverter);
		}
		if (this.authorizationResponseHandler != null) {
			authorizationEndpointFilter.setAuthenticationSuccessHandler(this.authorizationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			authorizationEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		if (StringUtils.hasText(this.consentPage)) {
			authorizationEndpointFilter.setConsentPage(this.consentPage);
		}
		builder.addFilterBefore(postProcess(authorizationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	private <B extends HttpSecurityBuilder<B>> List<AuthenticationProvider> createDefaultAuthenticationProviders(B builder) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

		OAuth2AuthorizationCodeRequestAuthenticationProvider authorizationCodeRequestAuthenticationProvider =
				new OAuth2AuthorizationCodeRequestAuthenticationProvider(
						OAuth2ConfigurerUtils.getRegisteredClientRepository(builder),
						OAuth2ConfigurerUtils.getAuthorizationService(builder),
						OAuth2ConfigurerUtils.getAuthorizationConsentService(builder));
		authenticationProviders.add(authorizationCodeRequestAuthenticationProvider);

		return authenticationProviders;
	}

}
