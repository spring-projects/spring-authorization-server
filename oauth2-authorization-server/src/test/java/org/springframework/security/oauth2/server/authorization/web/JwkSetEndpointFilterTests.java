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
package org.springframework.security.oauth2.server.authorization.web;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.key.AsymmetricKey;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.crypto.key.SymmetricKey;
import org.springframework.security.crypto.key.TestCryptoKeys;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link JwkSetEndpointFilter}.
 *
 * @author Joe Grandja
 */
public class JwkSetEndpointFilterTests {
	private CryptoKeySource keySource;
	private JwkSetEndpointFilter filter;

	@Before
	public void setUp() {
		this.keySource = mock(CryptoKeySource.class);
		this.filter = new JwkSetEndpointFilter(this.keySource);
	}

	@Test
	public void constructorWhenKeySourceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwkSetEndpointFilter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("keySource cannot be null");
	}

	@Test
	public void constructorWhenJwkSetEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwkSetEndpointFilter(this.keySource, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwkSetEndpointUri cannot be empty");
	}

	@Test
	public void doFilterWhenNotJwkSetRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenJwkSetRequestPostThenNotProcessed() throws Exception {
		String requestUri = JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAsymmetricKeysThenJwkSetResponse() throws Exception {
		AsymmetricKey rsaKey = TestCryptoKeys.rsaKey().build();
		AsymmetricKey ecKey = TestCryptoKeys.ecKey().build();
		when(this.keySource.getKeys()).thenReturn(
				Stream.of(rsaKey, ecKey).collect(Collectors.toSet()));

		String requestUri = JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

		JWKSet jwkSet = JWKSet.parse(response.getContentAsString());
		assertThat(jwkSet.getKeys()).hasSize(2);

		RSAKey rsaJwk = (RSAKey) jwkSet.getKeyByKeyId(rsaKey.getId());
		assertThat(rsaJwk).isNotNull();
		assertThat(rsaJwk.toRSAPublicKey()).isEqualTo(rsaKey.getPublicKey());
		assertThat(rsaJwk.toRSAPrivateKey()).isNull();
		assertThat(rsaJwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(rsaJwk.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

		ECKey ecJwk = (ECKey) jwkSet.getKeyByKeyId(ecKey.getId());
		assertThat(ecJwk).isNotNull();
		assertThat(ecJwk.toECPublicKey()).isEqualTo(ecKey.getPublicKey());
		assertThat(ecJwk.toECPublicKey()).isEqualTo(ecKey.getPublicKey());
		assertThat(ecJwk.toECPrivateKey()).isNull();
		assertThat(ecJwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(ecJwk.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
	}

	@Test
	public void doFilterWhenSymmetricKeysThenJwkSetResponseEmpty() throws Exception {
		SymmetricKey secretKey = TestCryptoKeys.secretKey().build();
		when(this.keySource.getKeys()).thenReturn(
				new HashSet<>(Collections.singleton(secretKey)));

		String requestUri = JwkSetEndpointFilter.DEFAULT_JWK_SET_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

		JWKSet jwkSet = JWKSet.parse(response.getContentAsString());
		assertThat(jwkSet.getKeys()).isEmpty();
	}
}
