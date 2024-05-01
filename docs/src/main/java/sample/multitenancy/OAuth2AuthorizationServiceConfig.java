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
package sample.multitenancy;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServiceConfig {

	@Bean
	public OAuth2AuthorizationService authorizationService(
			@Qualifier("issuer1-data-source") DataSource issuer1DataSource,
			@Qualifier("issuer2-data-source") DataSource issuer2DataSource,
			TenantPerIssuerComponentRegistry componentRegistry,
			RegisteredClientRepository registeredClientRepository) {

		componentRegistry.register("issuer1", OAuth2AuthorizationService.class,
				new JdbcOAuth2AuthorizationService(	// <1>
						new JdbcTemplate(issuer1DataSource), registeredClientRepository));
		componentRegistry.register("issuer2", OAuth2AuthorizationService.class,
				new JdbcOAuth2AuthorizationService(	// <2>
						new JdbcTemplate(issuer2DataSource), registeredClientRepository));

		return new DelegatingOAuth2AuthorizationService(componentRegistry);
	}

	private static class DelegatingOAuth2AuthorizationService implements OAuth2AuthorizationService {	// <3>

		private final TenantPerIssuerComponentRegistry componentRegistry;

		private DelegatingOAuth2AuthorizationService(TenantPerIssuerComponentRegistry componentRegistry) {
			this.componentRegistry = componentRegistry;
		}

		@Override
		public void save(OAuth2Authorization authorization) {
			OAuth2AuthorizationService authorizationService = getAuthorizationService();
			if (authorizationService != null) {
				authorizationService.save(authorization);
			}
		}

		@Override
		public void remove(OAuth2Authorization authorization) {
			OAuth2AuthorizationService authorizationService = getAuthorizationService();
			if (authorizationService != null) {
				authorizationService.remove(authorization);
			}
		}

		@Override
		public OAuth2Authorization findById(String id) {
			OAuth2AuthorizationService authorizationService = getAuthorizationService();
			return (authorizationService != null) ?
					authorizationService.findById(id) :
					null;
		}

		@Override
		public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
			OAuth2AuthorizationService authorizationService = getAuthorizationService();
			return (authorizationService != null) ?
					authorizationService.findByToken(token, tokenType) :
					null;
		}

		private OAuth2AuthorizationService getAuthorizationService() {
			return this.componentRegistry.get(OAuth2AuthorizationService.class);	// <4>
		}

	}

}
