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

import org.springframework.util.Assert;

/**
 * A representation of Unsecured JWT defined by JSON Web Token (JWT).
 *
 * @author Anoop Garlapati
 * @since 0.0.1
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-6">Unsecured JWT</a>
 */
public class UnsecuredJwt {
	private final JoseHeaders headers;
	private final JwtClaimsSet claimsSet;

	public UnsecuredJwt(JoseHeaders headers, JwtClaimsSet claimsSet) {
		Assert.notNull(headers, "headers cannot be null");
		Assert.notNull(claimsSet, "claimsSet cannot be null");
		this.headers = headers;
		this.claimsSet = claimsSet;
	}

	public JoseHeaders getHeaders() {
		return this.headers;
	}

	public JwtClaimsSet getClaimsSet() {
		return this.claimsSet;
	}
}
