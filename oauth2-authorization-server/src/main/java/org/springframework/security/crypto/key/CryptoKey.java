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

import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * A holder of a {@code java.security.Key} used for cryptographic operations.
 *
 * @param <K> the type of {@code java.security.Key}
 * @author Joe Grandja
 * @since 0.1.0
 * @see CryptoKeySource
 */
public class CryptoKey<K extends Key> implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final K key;
	private final String id;
	private final Map<String, Object> metadata;

	/**
	 * Constructs a {@code CryptoKey} using the provided parameters.
	 *
	 * @param key the {@code java.security.Key}
	 * @param id the logical identifier for the {@code key}
	 */
	protected CryptoKey(K key, String id) {
		this(key, id, Collections.emptyMap());
	}

	/**
	 * Constructs a {@code CryptoKey} using the provided parameters.
	 *
	 * @param key the {@code java.security.Key}
	 * @param id the logical identifier for the {@code key}
	 * @param metadata the metadata describing the {@code key}
	 */
	protected CryptoKey(K key, String id, Map<String, Object> metadata) {
		Assert.notNull(key, "key cannot be null");
		Assert.hasText(id, "id cannot be empty");
		Assert.notNull(metadata, "metadata cannot be null");
		this.key = key;
		this.id = id;
		this.metadata = Collections.unmodifiableMap(new LinkedHashMap<>(metadata));
	}

	/**
	 * Returns a type of {@code java.security.Key},
	 * e.g. {@code javax.crypto.SecretKey} or {@code java.security.PrivateKey}.
	 *
	 * @return the type of {@code java.security.Key}
	 */
	public final K getKey() {
		return this.key;
	}

	/**
	 * Returns the logical identifier for this key.
	 *
	 * @return the logical identifier for this key
	 */
	public final String getId() {
		return this.id;
	}

	/**
	 * Returns the metadata value associated to this key.
	 *
	 * @param name the name of the metadata
	 * @param <T> the type of the metadata
	 * @return the metadata value, or {@code null} if not available
	 */
	@SuppressWarnings("unchecked")
	public final <T> T getMetadata(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) this.metadata.get(name);
	}

	/**
	 * Returns the metadata associated to this key.
	 *
	 * @return a {@code Map} of the metadata
	 */
	public final Map<String, Object> getMetadata() {
		return this.metadata;
	}

	/**
	 * Returns the algorithm for this key.
	 *
	 * @return the algorithm for this key
	 */
	public final String getAlgorithm() {
		return getKey().getAlgorithm();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		CryptoKey<?> that = (CryptoKey<?>) obj;
		return Objects.equals(this.id, that.id);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.id);
	}

	/**
	 * Create a {@link SymmetricKey} via {@link SymmetricKey.Builder}.
	 *
	 * @param secretKey the {@code javax.crypto.SecretKey}
	 * @return the {@link SymmetricKey.Builder}
	 */
	public static SymmetricKey.Builder symmetric(SecretKey secretKey) {
		return new SymmetricKey.Builder(secretKey);
	}

	/**
	 * Create a {@link AsymmetricKey} via {@link AsymmetricKey.Builder}.
	 *
	 * @param privateKey the {@code java.security.PrivateKey}
	 * @param publicKey the {@code java.security.PublicKey}
	 * @return the {@link AsymmetricKey.Builder}
	 */
	public static AsymmetricKey.Builder asymmetric(PrivateKey privateKey, PublicKey publicKey) {
		return new AsymmetricKey.Builder(privateKey, publicKey);
	}

	/**
	 * Base builder for {@link CryptoKey}.
	 *
	 * @param <T> the type of {@link CryptoKey}
	 * @param <B> the type of {@link AbstractBuilder}
	 */
	protected abstract static class AbstractBuilder<T extends CryptoKey<?>, B extends AbstractBuilder<T, B>> implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		protected Key key;
		protected String id;
		protected Map<String, Object> metadata = new HashMap<>();

		/**
		 * Sub-class constructor.
		 *
		 * @param key the {@code java.security.Key}
		 */
		protected AbstractBuilder(Key key) {
			Assert.notNull(key, "key cannot be null");
			this.key = key;
		}

		/**
		 * Sets the logical identifier for this key.
		 *
		 * @param id the logical identifier for this key
		 * @return the type of {@link AbstractBuilder}
		 */
		@SuppressWarnings("unchecked")
		public B id(String id) {
			this.id = id;
			return (B) this;
		}

		/**
		 * Adds metadata for this key.
		 *
		 * @param name the name of the metadata
		 * @param value the value of the metadata
		 * @return the type of {@link AbstractBuilder}
		 */
		@SuppressWarnings("unchecked")
		public B metadata(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.metadata.put(name, value);
			return (B) this;
		}

		/**
		 * A {@code Consumer} of the metadata {@code Map}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param metadataConsumer a {@link Consumer} of the metadata {@code Map}
		 * @return the type of {@link AbstractBuilder}
		 */
		@SuppressWarnings("unchecked")
		public B metadata(Consumer<Map<String, Object>> metadataConsumer) {
			metadataConsumer.accept(this.metadata);
			return (B) this;
		}

		/**
		 * Creates the {@link CryptoKey}.
		 *
		 * @return the {@link CryptoKey}
		 */
		protected abstract T build();

	}
}
