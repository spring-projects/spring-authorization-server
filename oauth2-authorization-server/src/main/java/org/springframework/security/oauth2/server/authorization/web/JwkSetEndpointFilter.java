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
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.key.AsymmetricKey;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A {@code Filter} that processes JWK Set requests.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see CryptoKeySource
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">Section 5 JWK Set Format</a>
 */
public class JwkSetEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for JWK Set requests.
	 */
	public static final String DEFAULT_JWK_SET_ENDPOINT_URI = "/oauth2/jwks";

	private final CryptoKeySource keySource;
	private final RequestMatcher requestMatcher;

	/**
	 * Constructs a {@code JwkSetEndpointFilter} using the provided parameters.
	 *
	 * @param keySource the source for cryptographic keys
	 */
	public JwkSetEndpointFilter(CryptoKeySource keySource) {
		this(keySource, DEFAULT_JWK_SET_ENDPOINT_URI);
	}

	/**
	 * Constructs a {@code JwkSetEndpointFilter} using the provided parameters.
	 *
	 * @param keySource the source for cryptographic keys
	 * @param jwkSetEndpointUri the endpoint {@code URI} for JWK Set requests
	 */
	public JwkSetEndpointFilter(CryptoKeySource keySource, String jwkSetEndpointUri) {
		Assert.notNull(keySource, "keySource cannot be null");
		Assert.hasText(jwkSetEndpointUri, "jwkSetEndpointUri cannot be empty");
		this.keySource = keySource;
		this.requestMatcher = new AntPathRequestMatcher(jwkSetEndpointUri, HttpMethod.GET.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		JWKSet jwkSet = buildJwkSet();

		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		try (Writer writer = response.getWriter()) {
			writer.write(jwkSet.toString());
		}
	}

	private JWKSet buildJwkSet() {
		return new JWKSet(
				this.keySource.getKeys().stream()
						.filter(key -> AsymmetricKey.class.isAssignableFrom(key.getClass()))
						.map(AsymmetricKey.class::cast)
						.map(this::convert)
						.filter(Objects::nonNull)
						.collect(Collectors.toList())
		);
	}

	private JWK convert(AsymmetricKey asymmetricKey) {
		JWK jwk = null;
		if (asymmetricKey.getPublicKey() instanceof RSAPublicKey) {
			RSAPublicKey publicKey = (RSAPublicKey) asymmetricKey.getPublicKey();
			jwk = new RSAKey.Builder(publicKey)
					.keyUse(KeyUse.SIGNATURE)
					.algorithm(JWSAlgorithm.RS256)
					.keyID(asymmetricKey.getId())
					.build();
		} else if (asymmetricKey.getPublicKey() instanceof ECPublicKey) {
			ECPublicKey publicKey = (ECPublicKey) asymmetricKey.getPublicKey();
			Curve curve = Curve.forECParameterSpec(publicKey.getParams());
			jwk = new ECKey.Builder(curve, publicKey)
					.keyUse(KeyUse.SIGNATURE)
					.algorithm(JWSAlgorithm.ES256)
					.keyID(asymmetricKey.getId())
					.build();
		}
		return jwk;
	}
}
