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
package org.springframework.security.oauth2.server.authorization.token;

import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Holds metadata associated to an OAuth 2.0 Token.
 *
 * @author Joe Grandja
 * @since 0.0.3
 * @see OAuth2Tokens
 */
public class OAuth2TokenMetadata implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	protected static final String TOKEN_METADATA_BASE = "token.metadata.";

	/**
	 * The name of the metadata that indicates if the token has been invalidated.
	 */
	public static final String INVALIDATED = TOKEN_METADATA_BASE.concat("invalidated");

	private final Map<String, Object> metadata;

	protected OAuth2TokenMetadata(Map<String, Object> metadata) {
		this.metadata = Collections.unmodifiableMap(new HashMap<>(metadata));
	}

	/**
	 * Returns {@code true} if the token has been invalidated (e.g. revoked).
	 * The default is {@code false}.
	 *
	 * @return {@code true} if the token has been invalidated, {@code false} otherwise
	 */
	public boolean isInvalidated() {
		return getMetadata(INVALIDATED);
	}

	/**
	 * Returns the value of the metadata associated to the token.
	 *
	 * @param name the name of the metadata
	 * @param <T> the type of the metadata
	 * @return the value of the metadata, or {@code null} if not available
	 */
	@SuppressWarnings("unchecked")
	public <T> T getMetadata(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) this.metadata.get(name);
	}

	/**
	 * Returns the metadata associated to the token.
	 *
	 * @return a {@code Map} of the metadata
	 */
	public Map<String, Object> getMetadata() {
		return this.metadata;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OAuth2TokenMetadata that = (OAuth2TokenMetadata) obj;
		return Objects.equals(this.metadata, that.metadata);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.metadata);
	}

	/**
	 * Returns a new {@link Builder}.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link OAuth2TokenMetadata}.
	 */
	public static class Builder implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		private final Map<String, Object> metadata = defaultMetadata();

		protected Builder() {
		}

		/**
		 * Set the token as invalidated (e.g. revoked).
		 *
		 * @return the {@link Builder}
		 */
		public Builder invalidated() {
			metadata(INVALIDATED, true);
			return this;
		}

		/**
		 * Adds a metadata associated to the token.
		 *
		 * @param name the name of the metadata
		 * @param value the value of the metadata
		 * @return the {@link Builder}
		 */
		public Builder metadata(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.metadata.put(name, value);
			return this;
		}

		/**
		 * A {@code Consumer} of the metadata {@code Map}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param metadataConsumer a {@link Consumer} of the metadata {@code Map}
		 * @return the {@link Builder}
		 */
		public Builder metadata(Consumer<Map<String, Object>> metadataConsumer) {
			metadataConsumer.accept(this.metadata);
			return this;
		}

		/**
		 * Builds a new {@link OAuth2TokenMetadata}.
		 *
		 * @return the {@link OAuth2TokenMetadata}
		 */
		public OAuth2TokenMetadata build() {
			return new OAuth2TokenMetadata(this.metadata);
		}

		protected static Map<String, Object> defaultMetadata() {
			Map<String, Object> metadata = new HashMap<>();
			metadata.put(INVALIDATED, false);
			return metadata;
		}
	}
}
