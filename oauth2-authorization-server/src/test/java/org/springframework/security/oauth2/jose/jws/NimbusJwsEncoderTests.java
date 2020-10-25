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
package org.springframework.security.oauth2.jose.jws;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.crypto.key.AsymmetricKey;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.crypto.key.TestCryptoKeys;
import org.springframework.security.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jose.JoseHeaderNames;
import org.springframework.security.oauth2.jose.TestJoseHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.TestJwtClaimsSets;

import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link NimbusJwsEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJwsEncoderTests {
	private CryptoKeySource keySource;
	private NimbusJwsEncoder jwtEncoder;

	@Before
	public void setUp() {
		this.keySource = mock(CryptoKeySource.class);
		this.jwtEncoder = new NimbusJwsEncoder(this.keySource);
	}

	@Test
	public void constructorWhenKeySourceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new NimbusJwsEncoder(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("keySource cannot be null");
	}

	@Test
	public void encodeWhenHeadersNullThenThrowIllegalArgumentException() {
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatThrownBy(() -> this.jwtEncoder.encode(null, jwtClaimsSet))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("headers cannot be null");
	}

	@Test
	public void encodeWhenClaimsNullThenThrowIllegalArgumentException() {
		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();

		assertThatThrownBy(() -> this.jwtEncoder.encode(joseHeader, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("claims cannot be null");
	}

	@Test
	public void encodeWhenUnsupportedKeyThenThrowJwtEncodingException() {
		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatThrownBy(() -> this.jwtEncoder.encode(joseHeader, jwtClaimsSet))
				.isInstanceOf(JwtEncodingException.class)
				.hasMessageContaining("Unsupported key for algorithm 'RS256'");
	}

	@Test
	public void encodeWhenUnsupportedKeyAlgorithmThenThrowJwtEncodingException() {
		JoseHeader joseHeader = TestJoseHeaders.joseHeader(SignatureAlgorithm.ES256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatThrownBy(() -> this.jwtEncoder.encode(joseHeader, jwtClaimsSet))
				.isInstanceOf(JwtEncodingException.class)
				.hasMessageContaining("Unsupported key for algorithm 'ES256'");
	}

	@Test
	public void encodeWhenUnsupportedKeyTypeThenThrowJwtEncodingException() {
		AsymmetricKey ecKey = TestCryptoKeys.ecKey().build();
		when(this.keySource.getKeys()).thenReturn(Collections.singleton(ecKey));

		JoseHeader joseHeader = TestJoseHeaders.joseHeader(SignatureAlgorithm.ES256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatThrownBy(() -> this.jwtEncoder.encode(joseHeader, jwtClaimsSet))
				.isInstanceOf(JwtEncodingException.class)
				.hasMessageContaining("Unsupported key type 'EC'");
	}

	@Test
	public void encodeWhenSuccessThenDecodes() {
		AsymmetricKey rsaKey = TestCryptoKeys.rsaKey().build();
		when(this.keySource.getKeys()).thenReturn(Collections.singleton(rsaKey));

		JoseHeader joseHeader = TestJoseHeaders.joseHeader()
				.headers(headers -> headers.remove(JoseHeaderNames.CRIT))
				.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt jws = this.jwtEncoder.encode(joseHeader, jwtClaimsSet);

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) rsaKey.getPublicKey()).build();
		jwtDecoder.decode(jws.getTokenValue());
	}

	@Test
	public void encodeWhenMultipleActiveKeysThenUseFirst() {
		AsymmetricKey rsaKey1 = TestCryptoKeys.rsaKey().build();
		AsymmetricKey rsaKey2 = TestCryptoKeys.rsaKey().build();
		when(this.keySource.getKeys()).thenReturn(
				Stream.of(rsaKey1, rsaKey2)
						.collect(Collectors.toCollection(LinkedHashSet::new)));

		JoseHeader joseHeader = TestJoseHeaders.joseHeader()
				.headers(headers -> headers.remove(JoseHeaderNames.CRIT))
				.build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt jws = this.jwtEncoder.encode(joseHeader, jwtClaimsSet);

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) rsaKey1.getPublicKey()).build();
		jwtDecoder.decode(jws.getTokenValue());
	}
}
