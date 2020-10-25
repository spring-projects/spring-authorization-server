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

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.UUID;

/**
 * A {@link CryptoKey} that holds a {@code java.security.PrivateKey}
 * and {@code java.security.PublicKey} used for asymmetric algorithm's.
 *
 * @author Joe Grandja
 * @since 0.1.0
 * @see CryptoKey
 * @see PrivateKey
 * @see PublicKey
 */
public final class AsymmetricKey extends CryptoKey<PrivateKey> {
	private final PublicKey publicKey;

	private AsymmetricKey(PrivateKey privateKey, PublicKey publicKey, String id, Map<String, Object> metadata) {
		super(privateKey, id, metadata);
		this.publicKey = publicKey;
	}

	/**
	 * Returns the {@code java.security.PublicKey}.
	 *
	 * @return the {@code java.security.PublicKey}
	 */
	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	/**
	 * A builder for {@link AsymmetricKey}.
	 */
	public static class Builder extends AbstractBuilder<AsymmetricKey, Builder> {
		private PublicKey publicKey;

		Builder(PrivateKey privateKey, PublicKey publicKey) {
			super(privateKey);
			Assert.notNull(publicKey, "publicKey cannot be null");
			this.publicKey = publicKey;
		}

		/**
		 * Creates the {@link AsymmetricKey}.
		 *
		 * @return the {@link AsymmetricKey}
		 */
		@Override
		public AsymmetricKey build() {
			if (!StringUtils.hasText(this.id)) {
				this.id = UUID.randomUUID().toString();
			}
			return new AsymmetricKey((PrivateKey) this.key, this.publicKey, this.id, this.metadata);
		}
	}
}
