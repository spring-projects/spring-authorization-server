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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertChainUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.ALG;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.B64;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.CRIT;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.CTY;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.JKU;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.JWK;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.KID;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.TYP;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.X5C;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.X5T;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.X5T256;
import static org.springframework.security.oauth2.server.authorization.jose.JoseHeaderNames.X5U;

/**
 * A low-level Nimbus implementation of {@link JwtEncoder} which takes a raw Nimbus configuration.
 *
 * @author Anoop Garlapati
 * @since 0.0.1
 */
public class NimbusJwtEncoder implements JwtEncoder {
	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to encode the Jwt: %s";

	private final JwsAlgorithm jwsAlgorithm;
	private final JWSSigner jwsSigner;
	private Consumer<JoseHeaders.Builder> joseHeadersCustomizer;
	private Consumer<JwtClaimsSet.Builder> jwtClaimsSetCustomizer;

	public NimbusJwtEncoder(JwsAlgorithm jwsAlgorithm, JWSSigner jwsSigner) {
		Assert.notNull(jwsAlgorithm, "jwsAlgorithm cannot be null");
		Assert.notNull(jwsSigner, "jwsSigner cannot be null");
		this.jwsAlgorithm = jwsAlgorithm;
		this.jwsSigner = jwsSigner;
	}

	@Override
	public Jwt encode(UnsecuredJwt unsecuredJwt) throws JwtException {
		// JWS Header
		JoseHeaders.Builder headersBuilder = new JoseHeaders.Builder(unsecuredJwt.getHeaders());
		if (jwsAlgorithm instanceof SignatureAlgorithm) {
			headersBuilder = headersBuilder.signatureAlgorithm((SignatureAlgorithm) jwsAlgorithm);
		} else if (jwsAlgorithm instanceof MacAlgorithm) {
			headersBuilder = headersBuilder.macAlgorithm((MacAlgorithm) jwsAlgorithm);
		}
		headersBuilder = headersBuilder.type("JWT");
		if (joseHeadersCustomizer != null) {
			joseHeadersCustomizer.accept(headersBuilder);
		}
		final JoseHeaders joseHeaders = headersBuilder.build();
		final JWSHeader jwsHeader = createJwsHeader(joseHeaders);

		// JWT Claims Set
		JwtClaimsSet.Builder claimsSetBuilder = new JwtClaimsSet.Builder(unsecuredJwt.getClaimsSet());
		if (jwtClaimsSetCustomizer != null) {
			jwtClaimsSetCustomizer.accept(claimsSetBuilder);
		}
		final JwtClaimsSet claimsSet = claimsSetBuilder.build();
		final JWTClaimsSet jwtClaimsSet = createJwtClaimsSet(claimsSet);

		// Nimbus JWT representation
		SignedJWT signedJwt = new SignedJWT(jwsHeader, jwtClaimsSet);
		try {
			// sign the Nimbus JWT
			signedJwt.sign(jwsSigner);
		} catch (JOSEException ex) {
			throw new JwtException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}

		// Build JWT with compact serialized value, headers and claims set
		return Jwt.withTokenValue(signedJwt.serialize())
				.headers(headers -> headers.putAll(joseHeaders.getHeaders()))
				.claims(claims -> claims.putAll(claimsSet.getClaims()))
				.build();
	}

	public void setJoseHeadersCustomizer(Consumer<JoseHeaders.Builder> joseHeadersCustomizer) {
		this.joseHeadersCustomizer = joseHeadersCustomizer;
	}

	public void setJwtClaimsSetCustomizer(Consumer<JwtClaimsSet.Builder> jwtClaimsSetCustomizer) {
		this.jwtClaimsSetCustomizer = jwtClaimsSetCustomizer;
	}

	@SuppressWarnings("StatementWithEmptyBody")
	private JWSHeader createJwsHeader(JoseHeaders headers) {
		JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(
				JWSAlgorithm.parse(headers.getHeaderAsString(ALG)));
		// Parse optional and custom header parameters
		Map<String, Object> headersMap = headers.getHeaders();
		try {
			for (final String name: headersMap.keySet()) {
				if (ALG.equals(name)) {
					// skip as alg is already set
				} else if (TYP.equals(name)) {
					String typValue = headers.getType();
					if (typValue != null) {
						jwsHeaderBuilder = jwsHeaderBuilder.type(new JOSEObjectType(typValue));
					}
				} else if (CTY.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.contentType(headers.getHeaderAsString(CTY));
				} else if (CRIT.equals(name)) {
					List<String> critValues = headers.getHeaderAsStringList(CRIT);
					if (critValues != null) {
						jwsHeaderBuilder = jwsHeaderBuilder.criticalParams(new HashSet<>(critValues));
					}
				} else if (JKU.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.jwkURL(headers.getHeaderAsURI(JKU));
				} else if (JWK.equals(name)) {
					String jwkAsString = headers.getHeaderAsString(JWK);
					if (jwkAsString != null) {
						jwsHeaderBuilder = jwsHeaderBuilder.jwk(com.nimbusds.jose.jwk.JWK.parse(jwkAsString));
					}
				} else if (X5U.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.x509CertURL(headers.getHeaderAsURI(X5U));
				} else if (X5T.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.x509CertThumbprint(
							Base64URL.from(headers.getHeaderAsString(X5T)));
				} else if (X5T256.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.x509CertSHA256Thumbprint(
							Base64URL.from(headers.getHeaderAsString(X5T256)));
				} else if (X5C.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.x509CertChain(
							X509CertChainUtils.toBase64List(JSONArrayUtils.parse(headers.getHeaderAsString(X5C))));
				} else if (KID.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.keyID(headers.getHeaderAsString(KID));
				} else if (B64.equals(name)) {
					jwsHeaderBuilder = jwsHeaderBuilder.base64URLEncodePayload(headers.getHeaderAsBoolean(B64));
				} else {
					jwsHeaderBuilder = jwsHeaderBuilder.customParam(name, headersMap.get(name));
				}
			}
		} catch (Exception ex) {
			throw new JwtException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
		return jwsHeaderBuilder.build();
	}

	private JWTClaimsSet createJwtClaimsSet(JwtClaimsSet claimsSet) {
		JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
		claimsSet.getClaims().forEach(jwtClaimsSetBuilder::claim);
		return jwtClaimsSetBuilder.build();
	}

	public static class KeyManagerJwtEncoderBuilder {
		private KeyManager keyManager;
		private JwsAlgorithm jwsAlgorithm;

		public KeyManagerJwtEncoderBuilder(KeyManager keyManager) {
			Assert.notNull(keyManager, "keyManager cannot be null");
			this.keyManager = keyManager;
			this.jwsAlgorithm = SignatureAlgorithm.RS256;
		}

		public KeyManagerJwtEncoderBuilder jwsAlgorithm(JwsAlgorithm jwsAlgorithm) {
			Assert.notNull(jwsAlgorithm, "jwsAlgorithm cannot be null");
			this.jwsAlgorithm = jwsAlgorithm;
			return this;
		}

		public NimbusJwtEncoder build() {
			Key key = keyManager.getActiveKey();
			JWSSigner jwsSigner;
			if (key instanceof RSAPrivateKey) {
				if (!JWSAlgorithm.Family.RSA.contains(JWSAlgorithm.parse(this.jwsAlgorithm.getName()))) {
					throw new IllegalStateException("The provided key is of type RSA; " +
							"however the JWS algorithm is of some other type: " +
							this.jwsAlgorithm + ". Please indicate one of RS256, RS384, or RS512.");
				}
				jwsSigner = new RSASSASigner((RSAPrivateKey) key);
			} else if (key instanceof SecretKey) {
				if (!JWSAlgorithm.Family.HMAC_SHA.contains(JWSAlgorithm.parse(this.jwsAlgorithm.getName()))) {
					throw new IllegalStateException("The provided key is of type HMAC_SHA; " +
							"however the JWS algorithm is of some other type: " +
							this.jwsAlgorithm + ". Please indicate one of HS256, HS384, or HS512.");
				}
				try {
					jwsSigner = new MACSigner((SecretKey) key);
				} catch (KeyLengthException ex) {
					throw new IllegalStateException("The provided secret key is invalid.", ex);
				}
			} else {
				throw new IllegalStateException("Unsupported key provided.");
			}
			return new NimbusJwtEncoder(jwsAlgorithm, jwsSigner);
		}
	}
}
