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
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;

/**
 * A {@code java.security.Key} that is managed by a {@link KeyManager}.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see KeyManager
 */
public final class ManagedKey implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private Key key;
	private PublicKey publicKey;
	private String keyId;
	private Instant activatedOn;
	private Instant deactivatedOn;

	private ManagedKey() {
	}

	/**
	 * Returns {@code true} if this is a symmetric key, {@code false} otherwise.
	 *
	 * @return {@code true} if this is a symmetric key, {@code false} otherwise
	 */
	public boolean isSymmetric() {
		return SecretKey.class.isAssignableFrom(this.key.getClass());
	}

	/**
	 * Returns {@code true} if this is a asymmetric key, {@code false} otherwise.
	 *
	 * @return {@code true} if this is a asymmetric key, {@code false} otherwise
	 */
	public boolean isAsymmetric() {
		return PrivateKey.class.isAssignableFrom(this.key.getClass());
	}

	/**
	 * Returns a type of {@code java.security.Key},
	 * e.g. {@code javax.crypto.SecretKey} or {@code java.security.PrivateKey}.
	 *
	 * @param <T> the type of {@code java.security.Key}
	 * @return the type of {@code java.security.Key}
	 */
	@SuppressWarnings("unchecked")
	public <T extends Key> T getKey() {
		return (T) this.key;
	}

	/**
	 * Returns the {@code java.security.PublicKey} if this is a asymmetric key, {@code null} otherwise.
	 *
	 * @return the {@code java.security.PublicKey} if this is a asymmetric key, {@code null} otherwise
	 */
	@Nullable
	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	/**
	 * Returns the key ID.
	 *
	 * @return the key ID
	 */
	public String getKeyId() {
		return this.keyId;
	}

	/**
	 * Returns the time when this key was activated.
	 *
	 * @return the time when this key was activated
	 */
	public Instant getActivatedOn() {
		return this.activatedOn;
	}

	/**
	 * Returns the time when this key was deactivated, {@code null} if still active.
	 *
	 * @return the time when this key was deactivated, {@code null} if still active
	 */
	@Nullable
	public Instant getDeactivatedOn() {
		return this.deactivatedOn;
	}

	/**
	 * Returns {@code true} if this key is active, {@code false} otherwise.
	 *
	 * @return {@code true} if this key is active, {@code false} otherwise
	 */
	public boolean isActive() {
		return getDeactivatedOn() == null;
	}

	/**
	 * Returns the key algorithm.
	 *
	 * @return the key algorithm
	 */
	public String getAlgorithm() {
		return this.key.getAlgorithm();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		ManagedKey that = (ManagedKey) obj;
		return Objects.equals(this.keyId, that.keyId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.keyId);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@code javax.crypto.SecretKey}.
	 *
	 * @param secretKey the {@code javax.crypto.SecretKey}
	 * @return the {@link Builder}
	 */
	public static Builder withSymmetricKey(SecretKey secretKey) {
		return new Builder(secretKey);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided
	 * {@code java.security.PublicKey} and {@code java.security.PrivateKey}.
	 *
	 * @param publicKey the {@code java.security.PublicKey}
	 * @param privateKey the {@code java.security.PrivateKey}
	 * @return the {@link Builder}
	 */
	public static Builder withAsymmetricKey(PublicKey publicKey, PrivateKey privateKey) {
		return new Builder(publicKey, privateKey);
	}

	/**
	 * A builder for {@link ManagedKey}.
	 */
	public static class Builder {
		private Key key;
		private PublicKey publicKey;
		private String keyId;
		private Instant activatedOn;
		private Instant deactivatedOn;

		private Builder(SecretKey secretKey) {
			Assert.notNull(secretKey, "secretKey cannot be null");
			this.key = secretKey;
		}

		private Builder(PublicKey publicKey, PrivateKey privateKey) {
			Assert.notNull(publicKey, "publicKey cannot be null");
			Assert.notNull(privateKey, "privateKey cannot be null");
			this.key = privateKey;
			this.publicKey = publicKey;
		}

		/**
		 * Sets the key ID.
		 *
		 * @param keyId the key ID
		 * @return the {@link Builder}
		 */
		public Builder keyId(String keyId) {
			this.keyId = keyId;
			return this;
		}

		/**
		 * Sets the time when this key was activated.
		 *
		 * @param activatedOn the time when this key was activated
		 * @return the {@link Builder}
		 */
		public Builder activatedOn(Instant activatedOn) {
			this.activatedOn = activatedOn;
			return this;
		}

		/**
		 * Sets the time when this key was deactivated.
		 *
		 * @param deactivatedOn the time when this key was deactivated
		 * @return the {@link Builder}
		 */
		public Builder deactivatedOn(Instant deactivatedOn) {
			this.deactivatedOn = deactivatedOn;
			return this;
		}

		/**
		 * Builds a new {@link ManagedKey}.
		 *
		 * @return a {@link ManagedKey}
		 */
		public ManagedKey build() {
			Assert.hasText(this.keyId, "keyId cannot be empty");
			Assert.notNull(this.activatedOn, "activatedOn cannot be null");

			ManagedKey managedKey = new ManagedKey();
			managedKey.key = this.key;
			managedKey.publicKey = this.publicKey;
			managedKey.keyId = this.keyId;
			managedKey.activatedOn = this.activatedOn;
			managedKey.deactivatedOn = this.deactivatedOn;
			return managedKey;
		}
	}
}
