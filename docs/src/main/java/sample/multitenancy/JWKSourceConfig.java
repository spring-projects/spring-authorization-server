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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

@Configuration(proxyBeanMethods = false)
public class JWKSourceConfig {

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		Map<String, JWKSet> jwkSetMap = new HashMap<>();
		jwkSetMap.put("issuer1", new JWKSet(generateRSAJwk()));	// <1>
		jwkSetMap.put("issuer2", new JWKSet(generateRSAJwk()));	// <2>

		return new DelegatingJWKSource(jwkSetMap);
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
		private final Map<String, JWKSet> jwkSetMap;

		private DelegatingJWKSource(Map<String, JWKSet> jwkSetMap) {
			this.jwkSetMap = jwkSetMap;
		}

		@Override
		public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
			JWKSet jwkSet = getJwkSet();
			return (jwkSet != null) ? jwkSelector.select(jwkSet) : Collections.emptyList();
		}

		private JWKSet getJwkSet() {
			if (AuthorizationServerContextHolder.getContext() == null ||
					AuthorizationServerContextHolder.getContext().getIssuer() == null) {
				return null;
			}
			String issuer = AuthorizationServerContextHolder.getContext().getIssuer();	// <4>
			for (Map.Entry<String, JWKSet> entry : this.jwkSetMap.entrySet()) {
				if (issuer.endsWith(entry.getKey())) {
					return entry.getValue();
				}
			}
			return null;
		}

	}

}
