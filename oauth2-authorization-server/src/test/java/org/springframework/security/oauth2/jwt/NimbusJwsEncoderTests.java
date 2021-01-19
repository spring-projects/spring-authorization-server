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
package org.springframework.security.oauth2.jwt;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.BiConsumer;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link NimbusJwsEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJwsEncoderTests {

	private List<JWK> jwkList;

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJwsEncoder jwsEncoder;

	@Before
	public void setUp() {
		this.jwkList = new ArrayList<>();
		this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
		this.jwsEncoder = new NimbusJwsEncoder(this.jwkSource);
	}

	@Test
	public void constructorWhenJwkSourceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NimbusJwsEncoder(null))
				.withMessage("jwkSource cannot be null");
	}

	@Test
	public void setJwtCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoder.setJwtCustomizer(null))
				.withMessage("jwtCustomizer cannot be null");
	}

	@Test
	public void encodeWhenHeadersNullThenThrowIllegalArgumentException() {
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoder.encode(null, jwtClaimsSet))
				.withMessage("headers cannot be null");
	}

	@Test
	public void encodeWhenClaimsNullThenThrowIllegalArgumentException() {
		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();

		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoder.encode(joseHeader, null))
				.withMessage("claims cannot be null");
	}

	@Test
	public void encodeWhenCustomizerSetThenCalled() {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		BiConsumer<JoseHeader.Builder, JwtClaimsSet.Builder> jwtCustomizer = mock(BiConsumer.class);
		this.jwsEncoder.setJwtCustomizer(jwtCustomizer);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		this.jwsEncoder.encode(joseHeader, jwtClaimsSet);

		verify(jwtCustomizer).accept(any(JoseHeader.Builder.class), any(JwtClaimsSet.Builder.class));
	}

	@Test
	public void encodeWhenJwkSelectFailedThenThrowJwtEncodingException() throws Exception {
		this.jwkSource = mock(JWKSource.class);
		this.jwsEncoder = new NimbusJwsEncoder(this.jwkSource);
		given(this.jwkSource.get(any(), any())).willThrow(new KeySourceException("key source error"));

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet))
				.withMessageContaining("Failed to select a JWK signing key -> key source error");
	}

	@Test
	public void encodeWhenJwkMultipleSelectedThenThrowJwtEncodingException() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);
		this.jwkList.add(rsaJwk);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet))
				.withMessageContaining("Found multiple JWK signing keys for algorithm 'RS256'");
	}

	@Test
	public void encodeWhenJwkSelectEmptyThenThrowJwtEncodingException() {
		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet))
				.withMessageContaining("Failed to select a JWK signing key");
	}

	@Test
	public void encodeWhenJwkKidNullThenThrowJwtEncodingException() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID(null)
				.build();
		// @formatter:on

		this.jwkList.add(rsaJwk);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet))
				.withMessageContaining("The \"kid\" (key ID) from the selected JWK cannot be empty");
	}

	@Test
	public void encodeWhenJwkUseEncryptionThenThrowJwtEncodingException() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		// @formatter:on

		this.jwkSource = mock(JWKSource.class);
		this.jwsEncoder = new NimbusJwsEncoder(this.jwkSource);
		given(this.jwkSource.get(any(), any())).willReturn(Collections.singletonList(rsaJwk));

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		assertThatExceptionOfType(JwtEncodingException.class)
				.isThrownBy(() -> this.jwsEncoder.encode(joseHeader, jwtClaimsSet)).withMessageContaining(
				"Failed to create a JWS Signer -> The JWK use must be sig (signature) or unspecified");
	}

	@Test
	public void encodeWhenSuccessThenDecodes() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwsEncoder.encode(joseHeader, jwtClaimsSet);

		// Assert headers/claims were added
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.TYP)).isEqualTo("JWT");
		assertThat(encodedJws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJws.getId()).isNotNull();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());
	}

	@Test
	public void encodeWhenKeysRotatedThenNewKeyUsed() throws Exception {
		TestJWKSource jwkSource = new TestJWKSource();
		JWKSource<SecurityContext> jwkSourceDelegate = spy(new JWKSource<SecurityContext>() {
			@Override
			public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
				return jwkSource.get(jwkSelector, context);
			}
		});
		NimbusJwsEncoder jwsEncoder = new NimbusJwsEncoder(jwkSourceDelegate);

		JwkListResultCaptor jwkListResultCaptor = new JwkListResultCaptor();
		willAnswer(jwkListResultCaptor).given(jwkSourceDelegate).get(any(), any());

		JoseHeader joseHeader = TestJoseHeaders.joseHeader().build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = jwsEncoder.encode(joseHeader, jwtClaimsSet);

		JWK jwk1 = jwkListResultCaptor.getResult().get(0);
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(((RSAKey) jwk1).toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());

		jwkSource.rotate(); // Trigger key rotation

		encodedJws = jwsEncoder.encode(joseHeader, jwtClaimsSet);

		JWK jwk2 = jwkListResultCaptor.getResult().get(0);
		jwtDecoder = NimbusJwtDecoder.withPublicKey(((RSAKey) jwk2).toRSAPublicKey()).build();
		jwtDecoder.decode(encodedJws.getTokenValue());

		assertThat(jwk1.getKeyID()).isNotEqualTo(jwk2.getKeyID());
	}

	private static final class JwkListResultCaptor implements Answer<List<JWK>> {

		private List<JWK> result;

		private List<JWK> getResult() {
			return this.result;
		}

		@SuppressWarnings("unchecked")
		@Override
		public List<JWK> answer(InvocationOnMock invocationOnMock) throws Throwable {
			this.result = (List<JWK>) invocationOnMock.callRealMethod();
			return this.result;
		}

	}

	private static final class TestJWKSource implements JWKSource<SecurityContext> {

		private int keyId = 1000;

		private JWKSet jwkSet;

		private TestJWKSource() {
			init();
		}

		@Override
		public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
			return jwkSelector.select(this.jwkSet);
		}

		private void init() {
			// @formatter:off
			RSAKey rsaJwk = TestJwks.jwk(TestKeys.DEFAULT_PUBLIC_KEY, TestKeys.DEFAULT_PRIVATE_KEY)
					.keyID("rsa-jwk-" + this.keyId++)
					.build();
			ECKey ecJwk = TestJwks.jwk((ECPublicKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPublic(), (ECPrivateKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPrivate())
					.keyID("ec-jwk-" + this.keyId++)
					.build();
			OctetSequenceKey secretJwk = TestJwks.jwk(TestKeys.DEFAULT_SECRET_KEY)
					.keyID("secret-jwk-" + this.keyId++)
					.build();
			// @formatter:on
			this.jwkSet = new JWKSet(Arrays.asList(rsaJwk, ecJwk, secretJwk));
		}

		private void rotate() {
			init();
		}

	}

}
