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

import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Map;
import java.util.UUID;

/**
 * A {@link CryptoKey} that holds a {@code javax.crypto.SecretKey}
 * used for symmetric algorithm's.
 *
 * @author Joe Grandja
 * @since 0.1.0
 * @see CryptoKey
 * @see SecretKey
 */
public final class SymmetricKey extends CryptoKey<SecretKey> {

	private SymmetricKey(SecretKey key, String id, Map<String, Object> metadata) {
		super(key, id, metadata);
	}

	/**
	 * A builder for {@link SymmetricKey}.
	 */
	public static class Builder extends AbstractBuilder<SymmetricKey, Builder> {

		Builder(SecretKey secretKey) {
			super(secretKey);
		}

		/**
		 * Creates the {@link SymmetricKey}.
		 *
		 * @return the {@link SymmetricKey}
		 */
		@Override
		public SymmetricKey build() {
			if (!StringUtils.hasText(this.id)) {
				this.id = UUID.randomUUID().toString();
			}
			return new SymmetricKey((SecretKey) this.key, this.id, this.metadata);
		}
	}
}
