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

import java.util.HashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationConsentServiceConfig {

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(
			@Qualifier("issuer1-data-source") DataSource issuer1DataSource,
			@Qualifier("issuer2-data-source") DataSource issuer2DataSource,
			RegisteredClientRepository registeredClientRepository) {

		Map<String, OAuth2AuthorizationConsentService> authorizationConsentServiceMap = new HashMap<>();
		authorizationConsentServiceMap.put("issuer1", new JdbcOAuth2AuthorizationConsentService(	// <1>
				new JdbcTemplate(issuer1DataSource), registeredClientRepository));
		authorizationConsentServiceMap.put("issuer2", new JdbcOAuth2AuthorizationConsentService(	// <2>
				new JdbcTemplate(issuer2DataSource), registeredClientRepository));

		return new DelegatingOAuth2AuthorizationConsentService(authorizationConsentServiceMap);
	}

	private static class DelegatingOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {	// <3>
		private final Map<String, OAuth2AuthorizationConsentService> authorizationConsentServiceMap;

		private DelegatingOAuth2AuthorizationConsentService(Map<String, OAuth2AuthorizationConsentService> authorizationConsentServiceMap) {
			this.authorizationConsentServiceMap = authorizationConsentServiceMap;
		}

		@Override
		public void save(OAuth2AuthorizationConsent authorizationConsent) {
			OAuth2AuthorizationConsentService authorizationConsentService = getAuthorizationConsentService();
			if (authorizationConsentService != null) {
				authorizationConsentService.save(authorizationConsent);
			}
		}

		@Override
		public void remove(OAuth2AuthorizationConsent authorizationConsent) {
			OAuth2AuthorizationConsentService authorizationConsentService = getAuthorizationConsentService();
			if (authorizationConsentService != null) {
				authorizationConsentService.remove(authorizationConsent);
			}
		}

		@Override
		public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
			OAuth2AuthorizationConsentService authorizationConsentService = getAuthorizationConsentService();
			return (authorizationConsentService != null) ?
					authorizationConsentService.findById(registeredClientId, principalName) :
					null;
		}

		private OAuth2AuthorizationConsentService getAuthorizationConsentService() {
			if (AuthorizationServerContextHolder.getContext() == null ||
					AuthorizationServerContextHolder.getContext().getIssuer() == null) {
				return null;
			}
			String issuer = AuthorizationServerContextHolder.getContext().getIssuer();	// <4>
			for (Map.Entry<String, OAuth2AuthorizationConsentService> entry : this.authorizationConsentServiceMap.entrySet()) {
				if (issuer.endsWith(entry.getKey())) {
					return entry.getValue();
				}
			}
			return null;
		}

	}

}
