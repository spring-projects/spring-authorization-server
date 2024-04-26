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
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

@Configuration(proxyBeanMethods = false)
public class RegisteredClientRepositoryConfig {

	@Bean
	public RegisteredClientRepository registeredClientRepository(
			@Qualifier("issuer1-data-source") DataSource issuer1DataSource,
			@Qualifier("issuer2-data-source") DataSource issuer2DataSource) {

		JdbcRegisteredClientRepository issuer1RegisteredClientRepository =
				new JdbcRegisteredClientRepository(new JdbcTemplate(issuer1DataSource));	// <1>

		// @fold:on
		// @formatter:off
		issuer1RegisteredClientRepository.save(
				RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("client-1")
						.clientSecret("{noop}secret")
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.scope("scope-1")
						.build()
		);
		// @formatter:on
		// @fold:off

		JdbcRegisteredClientRepository issuer2RegisteredClientRepository =
				new JdbcRegisteredClientRepository(new JdbcTemplate(issuer2DataSource));	// <2>

		// @fold:on
		// @formatter:off
		issuer2RegisteredClientRepository.save(
				RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("client-2")
						.clientSecret("{noop}secret")
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.scope("scope-2")
						.build()
		);
		// @formatter:on
		// @fold:off

		Map<String, RegisteredClientRepository> registeredClientRepositoryMap = new HashMap<>();
		registeredClientRepositoryMap.put("issuer1", issuer1RegisteredClientRepository);
		registeredClientRepositoryMap.put("issuer2", issuer2RegisteredClientRepository);

		return new DelegatingRegisteredClientRepository(registeredClientRepositoryMap);
	}

	private static class DelegatingRegisteredClientRepository implements RegisteredClientRepository {	// <3>
		private final Map<String, RegisteredClientRepository> registeredClientRepositoryMap;

		private DelegatingRegisteredClientRepository(Map<String, RegisteredClientRepository> registeredClientRepositoryMap) {
			this.registeredClientRepositoryMap = registeredClientRepositoryMap;
		}

		@Override
		public void save(RegisteredClient registeredClient) {
			RegisteredClientRepository registeredClientRepository = getRegisteredClientRepository();
			if (registeredClientRepository != null) {
				registeredClientRepository.save(registeredClient);
			}
		}

		@Override
		public RegisteredClient findById(String id) {
			RegisteredClientRepository registeredClientRepository = getRegisteredClientRepository();
			return (registeredClientRepository != null) ?
					registeredClientRepository.findById(id) :
					null;
		}

		@Override
		public RegisteredClient findByClientId(String clientId) {
			RegisteredClientRepository registeredClientRepository = getRegisteredClientRepository();
			return (registeredClientRepository != null) ?
					registeredClientRepository.findByClientId(clientId) :
					null;
		}

		private RegisteredClientRepository getRegisteredClientRepository() {
			if (AuthorizationServerContextHolder.getContext() == null ||
					AuthorizationServerContextHolder.getContext().getIssuer() == null) {
				return null;
			}
			String issuer = AuthorizationServerContextHolder.getContext().getIssuer();	// <4>
			for (Map.Entry<String, RegisteredClientRepository> entry : this.registeredClientRepositoryMap.entrySet()) {
				if (issuer.endsWith(entry.getKey())) {
					return entry.getValue();
				}
			}
			return null;
		}

	}

}
