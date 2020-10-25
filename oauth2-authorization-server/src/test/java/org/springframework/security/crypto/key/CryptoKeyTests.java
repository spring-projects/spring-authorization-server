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

import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.crypto.key.KeyGeneratorUtils.generateRsaKey;
import static org.springframework.security.crypto.key.KeyGeneratorUtils.generateSecretKey;

/**
 * Tests for {@link CryptoKey}.
 *
 * @author Joe Grandja
 */
public class CryptoKeyTests {
	private static SecretKey secretKey;
	private static KeyPair rsaKeyPair;

	@BeforeClass
	public static void init() {
		secretKey = generateSecretKey();
		rsaKeyPair = generateRsaKey();
	}

	@Test
	public void symmetricWhenSecretKeyNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> CryptoKey.symmetric(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("key cannot be null");
	}

	@Test
	public void metadataWhenNameNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> CryptoKey.symmetric(secretKey).metadata(null, "value"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void metadataWhenValueNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> CryptoKey.symmetric(secretKey).metadata("name", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void symmetricWhenAllAttributesProvidedThenAllAttributesAreSet() {
		Map<String, Object> keyMetadata = new HashMap<>();
		keyMetadata.put("name1", "value1");
		keyMetadata.put("name2", "value2");

		SymmetricKey symmetricKey = CryptoKey.symmetric(secretKey)
				.id("id")
				.metadata(metadata -> metadata.putAll(keyMetadata))
				.build();

		assertThat(symmetricKey.getKey()).isEqualTo(secretKey);
		assertThat(symmetricKey.getId()).isEqualTo("id");
		assertThat(symmetricKey.getMetadata()).isEqualTo(keyMetadata);
	}

	@Test
	public void asymmetricWhenPrivateKeyNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> CryptoKey.asymmetric(null, rsaKeyPair.getPublic()))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("key cannot be null");
	}

	@Test
	public void asymmetricWhenPublicKeyNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> CryptoKey.asymmetric(rsaKeyPair.getPrivate(), null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("publicKey cannot be null");
	}

	@Test
	public void asymmetricWhenAllAttributesProvidedThenAllAttributesAreSet() {
		Map<String, Object> keyMetadata = new HashMap<>();
		keyMetadata.put("name1", "value1");
		keyMetadata.put("name2", "value2");

		AsymmetricKey asymmetricKey = CryptoKey.asymmetric(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic())
				.id("id")
				.metadata(metadata -> metadata.putAll(keyMetadata))
				.build();

		assertThat(asymmetricKey.getKey()).isEqualTo(rsaKeyPair.getPrivate());
		assertThat(asymmetricKey.getPublicKey()).isEqualTo(rsaKeyPair.getPublic());
		assertThat(asymmetricKey.getId()).isEqualTo("id");
		assertThat(asymmetricKey.getMetadata()).isEqualTo(keyMetadata);
	}
}
