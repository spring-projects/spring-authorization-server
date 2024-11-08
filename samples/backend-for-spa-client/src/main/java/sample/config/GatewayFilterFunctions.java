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

import org.springframework.cloud.gateway.server.mvc.common.Shortcut;
import org.springframework.cloud.gateway.server.mvc.filter.SimpleFilterSupplier;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.cloud.gateway.server.mvc.common.MvcUtils.getApplicationContext;

/**
 * Custom {@code HandlerFilterFunction}'s registered in META-INF/spring.factories and used in application.yml.
 *
 * @author Joe Grandja
 * @since 1.4
 */
public interface GatewayFilterFunctions {

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> relayTokenIfExists(String clientRegistrationId) {
		return (request, next) -> {
			Authentication principal = (Authentication) request.servletRequest().getUserPrincipal();
			OAuth2AuthorizedClientRepository authorizedClientRepository = getApplicationContext(request)
					.getBean(OAuth2AuthorizedClientRepository.class);
			OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
					clientRegistrationId, principal, request.servletRequest());
			if (authorizedClient != null) {
				OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
				ServerRequest bearerRequest = ServerRequest.from(request)
						.headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken.getTokenValue())).build();
				return next.handle(bearerRequest);
			}
			return next.handle(request);
		};
	}

	class FilterSupplier extends SimpleFilterSupplier {

		FilterSupplier() {
			super(GatewayFilterFunctions.class);
		}

	}

}
