/*
 * Copyright 2020 the original author or authors.
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

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.oauth2.jose.jws.NimbusJwsEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.JwkSetEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see AbstractHttpConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationEndpointFilter
 * @see OAuth2TokenEndpointFilter
 * @see OAuth2ClientAuthenticationFilter
 */
public final class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {

	private final RequestMatcher authorizationEndpointMatcher = new AntPathRequestMatcher(
			OAuth2AuthorizationEndpointFilter.DEFAULT_AUTHORIZATION_ENDPOINT_URI, HttpMethod.GET.name());
	private final RequestMatcher tokenEndpointMatcher = new AntPathRequestMatcher(
			OAuth2TokenEndpointFilter.DEFAULT_TOKEN_ENDPOINT_URI, HttpMethod.POST.name());
	private final RequestMatcher jwkSetEndpointMatcher = new AntPathRequestMatcher(
			JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI, HttpMethod.GET.name());

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
	 * Sets the key manager.
	 *
	 * @param keyManager the key manager
	 * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
	 */
	public OAuth2AuthorizationServerConfigurer<B> keyManager(KeyManager keyManager) {
		Assert.notNull(keyManager, "keyManager cannot be null");
		this.getBuilder().setSharedObject(KeyManager.class, keyManager);
		return this;
	}

	/**
	 * Returns a {@code List} of {@link RequestMatcher}'s for the authorization server endpoints.
	 *
	 * @return a {@code List} of {@link RequestMatcher}'s for the authorization server endpoints
	 */
	public List<RequestMatcher> getEndpointMatchers() {
		return Arrays.asList(this.authorizationEndpointMatcher,
				this.tokenEndpointMatcher, this.jwkSetEndpointMatcher);
	}

	@Override
	public void init(B builder) {
		OAuth2ClientAuthenticationProvider clientAuthenticationProvider =
				new OAuth2ClientAuthenticationProvider(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder));
		builder.authenticationProvider(postProcess(clientAuthenticationProvider));

		NimbusJwsEncoder jwtEncoder = new NimbusJwsEncoder(getKeyManager(builder));

		OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider =
				new OAuth2AuthorizationCodeAuthenticationProvider(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder),
						jwtEncoder);
		builder.authenticationProvider(postProcess(authorizationCodeAuthenticationProvider));

		OAuth2ClientCredentialsAuthenticationProvider clientCredentialsAuthenticationProvider =
				new OAuth2ClientCredentialsAuthenticationProvider(
						getAuthorizationService(builder),
						jwtEncoder);
		builder.authenticationProvider(postProcess(clientCredentialsAuthenticationProvider));

		ExceptionHandlingConfigurer<B> exceptionHandling = builder.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			// Register the default AuthenticationEntryPoint for the token endpoint
			exceptionHandling.defaultAuthenticationEntryPointFor(
					new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), this.tokenEndpointMatcher);
		}
	}

	@Override
	public void configure(B builder) {
		JwkSetEndpointFilter jwkSetEndpointFilter = new JwkSetEndpointFilter(getKeyManager(builder));
		builder.addFilterBefore(postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

		OAuth2ClientAuthenticationFilter clientAuthenticationFilter = new OAuth2ClientAuthenticationFilter(
				authenticationManager, this.tokenEndpointMatcher);
		builder.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);

		OAuth2AuthorizationEndpointFilter authorizationEndpointFilter =
				new OAuth2AuthorizationEndpointFilter(
						getRegisteredClientRepository(builder),
						getAuthorizationService(builder));
		builder.addFilterBefore(postProcess(authorizationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

		OAuth2TokenEndpointFilter tokenEndpointFilter =
				new OAuth2TokenEndpointFilter(
						authenticationManager,
						getAuthorizationService(builder));
		builder.addFilterAfter(postProcess(tokenEndpointFilter), FilterSecurityInterceptor.class);
	}

	private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
		RegisteredClientRepository registeredClientRepository = builder.getSharedObject(RegisteredClientRepository.class);
		if (registeredClientRepository == null) {
			registeredClientRepository = getRegisteredClientRepositoryBean(builder);
			builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
		}
		return registeredClientRepository;
	}

	private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepositoryBean(B builder) {
		return builder.getSharedObject(ApplicationContext.class).getBean(RegisteredClientRepository.class);
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
		OAuth2AuthorizationService authorizationService = builder.getSharedObject(OAuth2AuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getAuthorizationServiceBean(builder);
			if (authorizationService == null) {
				authorizationService = new InMemoryOAuth2AuthorizationService();
			}
			builder.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationServiceBean(B builder) {
		Map<String, OAuth2AuthorizationService> authorizationServiceMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				builder.getSharedObject(ApplicationContext.class), OAuth2AuthorizationService.class);
		if (authorizationServiceMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(OAuth2AuthorizationService.class, authorizationServiceMap.size(),
					"Expected single matching bean of type '" + OAuth2AuthorizationService.class.getName() + "' but found " +
							authorizationServiceMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(authorizationServiceMap.keySet()));
		}
		return (!authorizationServiceMap.isEmpty() ? authorizationServiceMap.values().iterator().next() : null);
	}

	private static <B extends HttpSecurityBuilder<B>> KeyManager getKeyManager(B builder) {
		KeyManager keyManager = builder.getSharedObject(KeyManager.class);
		if (keyManager == null) {
			keyManager = getKeyManagerBean(builder);
			builder.setSharedObject(KeyManager.class, keyManager);
		}
		return keyManager;
	}

	private static <B extends HttpSecurityBuilder<B>> KeyManager getKeyManagerBean(B builder) {
		return builder.getSharedObject(ApplicationContext.class).getBean(KeyManager.class);
	}
}
