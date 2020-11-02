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

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;

/**
 * A token builder for JWT tokens. Allows to customize claims and headers of a JWT token.
 *
 * @see JwtClaimsSet
 * @see JoseHeader
 *
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class JwtBuilder implements OAuth2TokenBuilder<Jwt> {

	private final JoseHeader.Builder joseHeaderBuilder;
	private final JwtClaimsSet.Builder jwtClaimsSetBuilder;
	private final JwtEncoder jwtEncoder;

	private JwtBuilder(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
		this.joseHeaderBuilder = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256);
		this.jwtClaimsSetBuilder = JwtClaimsSet.builder();
	}

	/**
	 * Create a new token builder for JWT token with specified encoder.
	 * @param jwtEncoder the JWT encoder
	 * @return new {@link JwtBuilder}
	 */
	public static JwtBuilder withEncoder(JwtEncoder jwtEncoder) {
		return new JwtBuilder(jwtEncoder);
	}

	/**
	 * Claims set customizer. The given consumer will be invoked with pre-configured set of claims.
	 * @param  claimsCustomizer a {@code JwtClaimsSet} customizer
	 */
	public void claims(Consumer<Map<String, Object>> claimsCustomizer) {
		this.jwtClaimsSetBuilder.claims(claimsCustomizer);
	}

	/**
	 * Headers customizer. The given consumer will be invoked with pre-configured headers.
	 * @param headersCustomizer a {@code JoseHeader} customizer
	 */
	public void headers(Consumer<Map<String, Object>> headersCustomizer) {
		this.joseHeaderBuilder.headers(headersCustomizer);
	}

	@Override
	public Jwt build() {
		return this.jwtEncoder.encode(joseHeaderBuilder.build(), jwtClaimsSetBuilder.build());
	}
}
