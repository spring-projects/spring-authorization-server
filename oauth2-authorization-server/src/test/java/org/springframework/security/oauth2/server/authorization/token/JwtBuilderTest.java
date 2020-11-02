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

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.crypto.key.StaticKeyGeneratingCryptoKeySource;
import org.springframework.security.oauth2.jose.jws.NimbusJwsEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class JwtBuilderTest {

	private JwtBuilder tokenBuilder;

	@Before
	public void setUp() {
		JwtEncoder encoder = new NimbusJwsEncoder(new StaticKeyGeneratingCryptoKeySource());
		this.tokenBuilder = JwtBuilder.withEncoder(encoder);
	}

	@Test
	public void buildSetsDefaults() {
		this.tokenBuilder.claims(claims -> claims.put("test-claim", "test"));
		Jwt jwt = this.tokenBuilder.build();

		assertThat(jwt.getHeaders().get("alg")).isEqualTo(SignatureAlgorithm.RS256);
	}

	@Test
	public void buildReturnsNewJwtToken() {
		this.tokenBuilder.claims(claims -> claims.put("test-claim", "claim-value"));
		this.tokenBuilder.headers(headers -> headers.put("test-header", "header-value"));

		Jwt jwt = this.tokenBuilder.build();
		assertThat(jwt.getClaims()).containsEntry("test-claim", "claim-value");
		assertThat(jwt.getHeaders()).containsEntry("test-header", "header-value");
	}
}
