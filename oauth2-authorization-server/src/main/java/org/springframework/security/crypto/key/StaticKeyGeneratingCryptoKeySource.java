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

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.security.crypto.key.KeyGeneratorUtils.generateRsaKey;
import static org.springframework.security.crypto.key.KeyGeneratorUtils.generateSecretKey;

/**
 * An implementation of a {@link CryptoKeySource} that generates the {@link CryptoKey}'s when constructed.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Joe Grandja
 * @since 0.1.0
 * @see CryptoKeySource
 */
public final class StaticKeyGeneratingCryptoKeySource implements CryptoKeySource {
	private final Map<String, CryptoKey<?>> keys;

	public StaticKeyGeneratingCryptoKeySource() {
		this.keys = Collections.unmodifiableMap(generateKeys());
	}

	@Override
	public Set<CryptoKey<?>> getKeys() {
		return new HashSet<>(this.keys.values());
	}

	private static Map<String, CryptoKey<?>> generateKeys() {
		KeyPair rsaKeyPair = generateRsaKey();
		AsymmetricKey asymmetricKey = CryptoKey.asymmetric(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic()).build();

		SecretKey hmacKey = generateSecretKey();
		SymmetricKey symmetricKey = CryptoKey.symmetric(hmacKey).build();

		return Stream.of(asymmetricKey, symmetricKey)
				.collect(Collectors.toMap(CryptoKey::getId, v -> v));
	}
}
