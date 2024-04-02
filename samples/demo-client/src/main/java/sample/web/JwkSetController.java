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
package sample.web;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Joe Grandja
 * @since 1.3
 */
@RestController
public class JwkSetController {
	private final JWKSet jwkSet;

	public JwkSetController(SslBundles sslBundles) throws Exception {
		this.jwkSet = initJwkSet(sslBundles);
	}

	@GetMapping("/jwks")
	public Map<String, Object> getJwkSet() {
		return this.jwkSet.toJSONObject();
	}

	private static JWKSet initJwkSet(SslBundles sslBundles) throws Exception {
		SslBundle sslBundle = sslBundles.getBundle("self-signed-demo-client");
		KeyStore keyStore = sslBundle.getStores().getKeyStore();
		String alias = sslBundle.getKey().getAlias();

		Certificate certificate = keyStore.getCertificate(alias);

		RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) certificate.getPublicKey())
				.keyUse(KeyUse.SIGNATURE)
				.keyID(UUID.randomUUID().toString())
				.x509CertChain(Collections.singletonList(Base64.encode(certificate.getEncoded())))
				.build();

		return new JWKSet(rsaKey);
	}

}
