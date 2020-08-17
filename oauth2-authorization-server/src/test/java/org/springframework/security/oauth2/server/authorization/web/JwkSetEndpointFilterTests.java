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
import org.springframework.security.crypto.keys.KeyManager;
import org.springframework.security.crypto.keys.ManagedKey;
import org.springframework.security.crypto.keys.TestManagedKeys;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Instant;
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
	private KeyManager keyManager;
	private JwkSetEndpointFilter filter;

	@Before
	public void setUp() {
		this.keyManager = mock(KeyManager.class);
		this.filter = new JwkSetEndpointFilter(this.keyManager);
	}

	@Test
	public void constructorWhenKeyManagerNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwkSetEndpointFilter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("keyManager cannot be null");
	}

	@Test
	public void constructorWhenJwkSetEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwkSetEndpointFilter(this.keyManager, null))
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
		ManagedKey rsaManagedKey = TestManagedKeys.rsaManagedKey().build();
		ManagedKey ecManagedKey = TestManagedKeys.ecManagedKey().build();
		when(this.keyManager.getKeys()).thenReturn(
				Stream.of(rsaManagedKey, ecManagedKey).collect(Collectors.toSet()));

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

		RSAKey rsaJwk = (RSAKey) jwkSet.getKeyByKeyId(rsaManagedKey.getKeyId());
		assertThat(rsaJwk).isNotNull();
		assertThat(rsaJwk.toRSAPublicKey()).isEqualTo(rsaManagedKey.getPublicKey());
		assertThat(rsaJwk.toRSAPrivateKey()).isNull();
		assertThat(rsaJwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(rsaJwk.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

		ECKey ecJwk = (ECKey) jwkSet.getKeyByKeyId(ecManagedKey.getKeyId());
		assertThat(ecJwk).isNotNull();
		assertThat(ecJwk.toECPublicKey()).isEqualTo(ecManagedKey.getPublicKey());
		assertThat(ecJwk.toECPublicKey()).isEqualTo(ecManagedKey.getPublicKey());
		assertThat(ecJwk.toECPrivateKey()).isNull();
		assertThat(ecJwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
		assertThat(ecJwk.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
	}

	@Test
	public void doFilterWhenSymmetricKeysThenJwkSetResponseEmpty() throws Exception {
		ManagedKey secretManagedKey = TestManagedKeys.secretManagedKey().build();
		when(this.keyManager.getKeys()).thenReturn(
				new HashSet<>(Collections.singleton(secretManagedKey)));

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

	@Test
	public void doFilterWhenNoActiveKeysThenJwkSetResponseEmpty() throws Exception {
		ManagedKey rsaManagedKey = TestManagedKeys.rsaManagedKey().deactivatedOn(Instant.now()).build();
		ManagedKey ecManagedKey = TestManagedKeys.ecManagedKey().deactivatedOn(Instant.now()).build();
		when(this.keyManager.getKeys()).thenReturn(
				Stream.of(rsaManagedKey, ecManagedKey).collect(Collectors.toSet()));

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
