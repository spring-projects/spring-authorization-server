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
package org.springframework.security.oauth2.jose;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author Joe Grandja
 */
public class TestJoseHeaders {

	public static JoseHeader.Builder joseHeader() {
		return joseHeader(SignatureAlgorithm.RS256);
	}

	public static JoseHeader.Builder joseHeader(SignatureAlgorithm signatureAlgorithm) {
		return JoseHeader.withAlgorithm(signatureAlgorithm)
				.jwkSetUri("https://provider.com/oauth2/jwks")
				.jwk(rsaJwk())
				.keyId(UUID.randomUUID().toString())
				.x509Uri("https://provider.com/oauth2/x509")
				.x509CertificateChain(Arrays.asList("x509Cert1", "x509Cert2"))
				.x509SHA1Thumbprint("x509SHA1Thumbprint")
				.x509SHA256Thumbprint("x509SHA256Thumbprint")
				.critical(Collections.singleton("custom-header-name"))
				.type("JWT")
				.contentType("jwt-content-type")
				.header("custom-header-name", "custom-header-value");
	}

	private static Map<String, Object> rsaJwk() {
		Map<String, Object> rsaJwk = new HashMap<>();
		rsaJwk.put("kty", "RSA");
		rsaJwk.put("n", "modulus");
		rsaJwk.put("e", "exponent");
		return rsaJwk;
	}
}
