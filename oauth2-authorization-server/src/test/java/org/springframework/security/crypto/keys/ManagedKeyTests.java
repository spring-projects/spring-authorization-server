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

import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.crypto.keys.KeyGeneratorUtils.generateRsaKey;
import static org.springframework.security.crypto.keys.KeyGeneratorUtils.generateSecretKey;

/**
 * Tests for {@link ManagedKey}.
 *
 * @author Joe Grandja
 */
public class ManagedKeyTests {
	private static SecretKey secretKey;
	private static KeyPair rsaKeyPair;

	@BeforeClass
	public static void init() {
		secretKey = generateSecretKey();
		rsaKeyPair = generateRsaKey();
	}

	@Test
	public void withSymmetricKeyWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> ManagedKey.withSymmetricKey(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("secretKey cannot be null");
	}

	@Test
	public void buildWhenKeyIdNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> ManagedKey.withSymmetricKey(secretKey).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("keyId cannot be empty");
	}

	@Test
	public void buildWhenActivatedOnNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> ManagedKey.withSymmetricKey(secretKey).keyId("keyId").build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("activatedOn cannot be null");
	}

	@Test
	public void buildWhenSymmetricKeyAllAttributesProvidedThenAllAttributesAreSet() {
		ManagedKey expectedManagedKey = TestManagedKeys.secretManagedKey().build();

		ManagedKey managedKey = ManagedKey.withSymmetricKey(expectedManagedKey.getKey())
				.keyId(expectedManagedKey.getKeyId())
				.activatedOn(expectedManagedKey.getActivatedOn())
				.build();

		assertThat(managedKey.isSymmetric()).isTrue();
		assertThat(managedKey.<Key>getKey()).isInstanceOf(SecretKey.class);
		assertThat(managedKey.<SecretKey>getKey()).isEqualTo(expectedManagedKey.getKey());
		assertThat(managedKey.getPublicKey()).isNull();
		assertThat(managedKey.getKeyId()).isEqualTo(expectedManagedKey.getKeyId());
		assertThat(managedKey.getActivatedOn()).isEqualTo(expectedManagedKey.getActivatedOn());
		assertThat(managedKey.getDeactivatedOn()).isEqualTo(expectedManagedKey.getDeactivatedOn());
		assertThat(managedKey.isActive()).isTrue();
		assertThat(managedKey.getAlgorithm()).isEqualTo(expectedManagedKey.getAlgorithm());
	}

	@Test
	public void withAsymmetricKeyWhenPublicKeyNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> ManagedKey.withAsymmetricKey(null, rsaKeyPair.getPrivate()))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("publicKey cannot be null");
	}

	@Test
	public void withAsymmetricKeyWhenPrivateKeyNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> ManagedKey.withAsymmetricKey(rsaKeyPair.getPublic(), null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("privateKey cannot be null");
	}

	@Test
	public void buildWhenAsymmetricKeyAllAttributesProvidedThenAllAttributesAreSet() {
		ManagedKey expectedManagedKey = TestManagedKeys.rsaManagedKey().build();

		ManagedKey managedKey = ManagedKey.withAsymmetricKey(expectedManagedKey.getPublicKey(), expectedManagedKey.getKey())
				.keyId(expectedManagedKey.getKeyId())
				.activatedOn(expectedManagedKey.getActivatedOn())
				.build();

		assertThat(managedKey.isAsymmetric()).isTrue();
		assertThat(managedKey.<Key>getKey()).isInstanceOf(PrivateKey.class);
		assertThat(managedKey.<PrivateKey>getKey()).isEqualTo(expectedManagedKey.getKey());
		assertThat(managedKey.getPublicKey()).isNotNull();
		assertThat(managedKey.getKeyId()).isEqualTo(expectedManagedKey.getKeyId());
		assertThat(managedKey.getActivatedOn()).isEqualTo(expectedManagedKey.getActivatedOn());
		assertThat(managedKey.getDeactivatedOn()).isEqualTo(expectedManagedKey.getDeactivatedOn());
		assertThat(managedKey.isActive()).isTrue();
		assertThat(managedKey.getAlgorithm()).isEqualTo(expectedManagedKey.getAlgorithm());
	}
}
