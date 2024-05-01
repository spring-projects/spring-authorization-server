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
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class JWKSourceConfig {

	@Bean
	public JWKSource<SecurityContext> jwkSource(TenantPerIssuerComponentRegistry componentRegistry) {
		componentRegistry.register("issuer1", JWKSet.class, new JWKSet(generateRSAJwk()));	// <1>
		componentRegistry.register("issuer2", JWKSet.class, new JWKSet(generateRSAJwk()));	// <2>

		return new DelegatingJWKSource(componentRegistry);
	}

	// @fold:on
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

	private static class DelegatingJWKSource implements JWKSource<SecurityContext> {	// <3>

		private final TenantPerIssuerComponentRegistry componentRegistry;

		private DelegatingJWKSource(TenantPerIssuerComponentRegistry componentRegistry) {
			this.componentRegistry = componentRegistry;
		}

		@Override
		public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
			JWKSet jwkSet = getJwkSet();
			return (jwkSet != null) ? jwkSelector.select(jwkSet) : Collections.emptyList();
		}

		private JWKSet getJwkSet() {
			return this.componentRegistry.get(JWKSet.class);	// <4>
		}

	}

}
