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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
public class TenantService {

	private final TenantPerIssuerComponentRegistry componentRegistry;

	public TenantService(TenantPerIssuerComponentRegistry componentRegistry) {
		this.componentRegistry = componentRegistry;
	}

	public void createTenant(String tenantId) {
		EmbeddedDatabase dataSource = createDataSource(tenantId);
		JdbcTemplate jdbcOperations = new JdbcTemplate(dataSource);

		RegisteredClientRepository registeredClientRepository =
				new JdbcRegisteredClientRepository(jdbcOperations);
		this.componentRegistry.register(tenantId, RegisteredClientRepository.class, registeredClientRepository);

		OAuth2AuthorizationService authorizationService =
				new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
		this.componentRegistry.register(tenantId, OAuth2AuthorizationService.class, authorizationService);

		OAuth2AuthorizationConsentService authorizationConsentService =
				new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
		this.componentRegistry.register(tenantId, OAuth2AuthorizationConsentService.class, authorizationConsentService);

		JWKSet jwkSet = new JWKSet(generateRSAJwk());
		this.componentRegistry.register(tenantId, JWKSet.class, jwkSet);
	}

	// @fold:on
	private EmbeddedDatabase createDataSource(String tenantId) {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.setName(tenantId)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
	}

	private static RSAKey generateRSAJwk() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}

		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		// @formatter:off
		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
	}
	// @fold:off

}
