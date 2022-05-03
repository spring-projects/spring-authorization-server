/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2TokenContext} implementation used when encoding a {@link Jwt}.
 *
 * @author Joe Grandja
 * @since 0.1.0
 * @see OAuth2TokenContext
 * @see JwsHeader.Builder
 * @see JwtClaimsSet.Builder
 * @see JwtEncoder#encode(JwtEncoderParameters)
 */
public final class JwtEncodingContext implements OAuth2TokenContext {
	private final Map<Object, Object> context;

	private JwtEncodingContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns the {@link JwsHeader.Builder headers}
	 * allowing the ability to add, replace, or remove.
	 *
	 * @return the {@link JwsHeader.Builder}
	 */
	public JwsHeader.Builder getHeaders() {
		return get(JwsHeader.Builder.class);
	}

	/**
	 * Returns the {@link JwtClaimsSet.Builder claims}
	 * allowing the ability to add, replace, or remove.
	 *
	 * @return the {@link JwtClaimsSet.Builder}
	 */
	public JwtClaimsSet.Builder getClaims() {
		return get(JwtClaimsSet.Builder.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided headers and claims.
	 *
	 * @param headersBuilder the headers to initialize the builder
	 * @param claimsBuilder the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder with(JwsHeader.Builder headersBuilder, JwtClaimsSet.Builder claimsBuilder) {
		return new Builder(headersBuilder, claimsBuilder);
	}

	/**
	 * A builder for {@link JwtEncodingContext}.
	 */
	public static final class Builder extends AbstractBuilder<JwtEncodingContext, Builder> {

		private Builder(JwsHeader.Builder headersBuilder, JwtClaimsSet.Builder claimsBuilder) {
			Assert.notNull(headersBuilder, "headersBuilder cannot be null");
			Assert.notNull(claimsBuilder, "claimsBuilder cannot be null");
			put(JwsHeader.Builder.class, headersBuilder);
			put(JwtClaimsSet.Builder.class, claimsBuilder);
		}

		/**
		 * A {@code Consumer} of the {@link JwsHeader.Builder headers}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @deprecated Use {@link #getHeaders()} instead
		 * @param headersConsumer a {@code Consumer} of the {@link JwsHeader.Builder headers}
		 * @return the {@link Builder} for further configuration
		 */
		@Deprecated
		public Builder headers(Consumer<JwsHeader.Builder> headersConsumer) {
			headersConsumer.accept(get(JwsHeader.Builder.class));
			return this;
		}

		/**
		 * A {@code Consumer} of the {@link JwtClaimsSet.Builder claims}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @deprecated Use {@link #getClaims()} instead
		 * @param claimsConsumer a {@code Consumer} of the {@link JwtClaimsSet.Builder claims}
		 * @return the {@link Builder} for further configuration
		 */
		@Deprecated
		public Builder claims(Consumer<JwtClaimsSet.Builder> claimsConsumer) {
			claimsConsumer.accept(get(JwtClaimsSet.Builder.class));
			return this;
		}

		/**
		 * Builds a new {@link JwtEncodingContext}.
		 *
		 * @return the {@link JwtEncodingContext}
		 */
		public JwtEncodingContext build() {
			return new JwtEncodingContext(getContext());
		}

	}

}
