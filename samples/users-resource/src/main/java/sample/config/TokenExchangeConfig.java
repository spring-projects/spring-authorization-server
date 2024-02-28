/*
 * Copyright 2020-2024 the original author or authors.
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
package sample.config;

import java.util.function.Function;

import sample.authorization.TokenExchangeOAuth2AuthorizedClientProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
@Configuration
public class TokenExchangeConfig {

	private static final String ACTOR_TOKEN_CLIENT_REGISTRATION_ID = "messaging-client-client-credentials";

	@Bean
	public OAuth2AuthorizedClientProvider tokenExchange(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService) {

		OAuth2AuthorizedClientManager authorizedClientManager = tokenExchangeAuthorizedClientManager(
				clientRegistrationRepository, authorizedClientService);
		Function<OAuth2AuthorizationContext, String> actorTokenResolver = createTokenResolver(authorizedClientManager,
				ACTOR_TOKEN_CLIENT_REGISTRATION_ID);

		TokenExchangeOAuth2AuthorizedClientProvider tokenExchangeAuthorizedClientProvider =
				new TokenExchangeOAuth2AuthorizedClientProvider();
		tokenExchangeAuthorizedClientProvider.setActorTokenResolver(actorTokenResolver);

		return tokenExchangeAuthorizedClientProvider;
	}

	/**
	 * Create a standalone {@link OAuth2AuthorizedClientManager} for resolving the actor token
	 * using {@code client_credentials}.
	 */
	private static OAuth2AuthorizedClientManager tokenExchangeAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService) {

		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.clientCredentials()
						.build();
		AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(
						clientRegistrationRepository, authorizedClientService);
		// @formatter:on
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		return authorizedClientManager;
	}

	/**
	 * Create a {@code Function} to resolve a token from the current principal.
	 */
	private static Function<OAuth2AuthorizationContext, String> createTokenResolver(
			OAuth2AuthorizedClientManager authorizedClientManager, String clientRegistrationId) {

		return (context) -> {
			// @formatter:off
			OAuth2AuthorizeRequest authorizeRequest =
					OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
							.principal(context.getPrincipal())
							.build();
			// @formatter:on

			OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
			Assert.notNull(authorizedClient, "authorizedClient cannot be null");

			return authorizedClient.getAccessToken().getTokenValue();
		};
	}

}
