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
package org.springframework.security.crypto.keys;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.security.crypto.keys.KeyGeneratorUtils.generateRsaKey;
import static org.springframework.security.crypto.keys.KeyGeneratorUtils.generateSecretKey;

/**
 * An implementation of a {@link KeyManager} that generates the {@link ManagedKey}(s) when constructed.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see KeyManager
 */
public final class StaticKeyGeneratingKeyManager implements KeyManager {
	private final Map<String, ManagedKey> keys;

	public StaticKeyGeneratingKeyManager() {
		this.keys = Collections.unmodifiableMap(new HashMap<>(generateKeys()));
	}

	@Nullable
	@Override
	public ManagedKey findByKeyId(String keyId) {
		Assert.hasText(keyId, "keyId cannot be empty");
		return this.keys.get(keyId);
	}

	@Override
	public Set<ManagedKey> findByAlgorithm(String algorithm) {
		Assert.hasText(algorithm, "algorithm cannot be empty");
		return this.keys.values().stream()
				.filter(managedKey -> managedKey.getAlgorithm().equals(algorithm))
				.collect(Collectors.toSet());
	}

	@Override
	public Set<ManagedKey> getKeys() {
		return new HashSet<>(this.keys.values());
	}

	private static Map<String, ManagedKey> generateKeys() {
		KeyPair rsaKeyPair = generateRsaKey();
		ManagedKey rsaManagedKey = ManagedKey.withAsymmetricKey(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate())
				.keyId(UUID.randomUUID().toString())
				.activatedOn(Instant.now())
				.build();

		SecretKey hmacKey = generateSecretKey();
		ManagedKey secretManagedKey = ManagedKey.withSymmetricKey(hmacKey)
				.keyId(UUID.randomUUID().toString())
				.activatedOn(Instant.now())
				.build();

		return Stream.of(rsaManagedKey, secretManagedKey)
				.collect(Collectors.toMap(ManagedKey::getKeyId, v -> v));
	}
}
