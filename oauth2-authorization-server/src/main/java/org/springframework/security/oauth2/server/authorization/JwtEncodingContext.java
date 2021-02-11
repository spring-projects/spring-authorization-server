/*
 * Copyright 2020-2021 the original author or authors.
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

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.context.Context;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.util.Assert;

/**
 * @author Joe Grandja
 * @since 0.1.0
 * @see OAuth2TokenContext
 * @see JoseHeader.Builder
 * @see JwtClaimsSet.Builder
 */
public final class JwtEncodingContext implements OAuth2TokenContext {
	private final Context context;

	private JwtEncodingContext(Map<Object, Object> context) {
		this.context = Context.of(context);
	}

	@Nullable
	@Override
	public <V> V get(Object key) {
		return this.context.get(key);
	}

	@Override
	public boolean hasKey(Object key) {
		return this.context.hasKey(key);
	}

	public JoseHeader.Builder getHeaders() {
		return get(JoseHeader.Builder.class);
	}

	public JwtClaimsSet.Builder getClaims() {
		return get(JwtClaimsSet.Builder.class);
	}

	public static Builder with(JoseHeader.Builder headersBuilder, JwtClaimsSet.Builder claimsBuilder) {
		return new Builder(headersBuilder, claimsBuilder);
	}

	public static final class Builder extends AbstractBuilder<JwtEncodingContext, Builder> {

		private Builder(JoseHeader.Builder headersBuilder, JwtClaimsSet.Builder claimsBuilder) {
			Assert.notNull(headersBuilder, "headersBuilder cannot be null");
			Assert.notNull(claimsBuilder, "claimsBuilder cannot be null");
			put(JoseHeader.Builder.class, headersBuilder);
			put(JwtClaimsSet.Builder.class, claimsBuilder);
		}

		public Builder headers(Consumer<JoseHeader.Builder> headersConsumer) {
			headersConsumer.accept(get(JoseHeader.Builder.class));
			return this;
		}

		public Builder claims(Consumer<JwtClaimsSet.Builder> claimsConsumer) {
			claimsConsumer.accept(get(JwtClaimsSet.Builder.class));
			return this;
		}

		public JwtEncodingContext build() {
			return new JwtEncodingContext(this.context);
		}
	}
}
