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
package org.springframework.security.oauth2.server.authorization.jose;

import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A representation of &quot;claims&quot; that may be contained
 * in the JSON object JWT Claims Set of a JSON Web Token (JWT).
 *
 * @author Anoop Garlapati
 * @since 0.0.1
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-4">JWT Claims</a>
 */
public class JwtClaimsSet implements JwtClaimAccessor {

	private final Map<String, Object> claims;

	protected JwtClaimsSet(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be null");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	public static class Builder {
		private Map<String, Object> claims = new LinkedHashMap<>();

		public Builder() {
		}

		public Builder(JwtClaimsSet jwtClaimsSet) {
			Assert.notNull(jwtClaimsSet, "jwtClaimsSet cannot be null");
			this.claims = jwtClaimsSet.claims;
		}

		public Builder claim(String name, Object value) {
			Assert.notNull(name, "name cannot be null");
			this.claims.put(name, value);
			return this;
		}

		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			Assert.notNull(claimsConsumer, "claimsConsumer cannot be null");
			claimsConsumer.accept(this.claims);
			return this;
		}

		public JwtClaimsSet build() {
			return new JwtClaimsSet(this.claims);
		}
	}
}
