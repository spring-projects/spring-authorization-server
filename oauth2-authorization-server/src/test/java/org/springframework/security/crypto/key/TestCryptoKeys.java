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
package org.springframework.security.crypto.key;

import java.security.KeyPair;

import static org.springframework.security.crypto.key.KeyGeneratorUtils.generateEcKey;
import static org.springframework.security.crypto.key.KeyGeneratorUtils.generateRsaKey;
import static org.springframework.security.crypto.key.KeyGeneratorUtils.generateSecretKey;

/**
 * @author Joe Grandja
 */
public class TestCryptoKeys {

	public static SymmetricKey.Builder secretKey() {
		return CryptoKey.symmetric(generateSecretKey());
	}

	public static AsymmetricKey.Builder rsaKey() {
		KeyPair rsaKeyPair = generateRsaKey();
		return CryptoKey.asymmetric(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic());
	}

	public static AsymmetricKey.Builder ecKey() {
		KeyPair ecKeyPair = generateEcKey();
		return CryptoKey.asymmetric(ecKeyPair.getPrivate(), ecKeyPair.getPublic());
	}
}
