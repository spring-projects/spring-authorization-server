/*
 * Copyright 2020-2022 the original author or authors.
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

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.jose.JwaAlgorithm;
import org.springframework.util.Assert;

/**
 * The JOSE header is a JSON object representing the header parameters of a JSON Web Token,
 * whether the JWT is a JWS or JWE, that describe the cryptographic operations applied to the JWT
 * and optionally, additional properties of the JWT.
 *
 * @author Anoop Garlapati
 * @author Joe Grandja
 * @since 0.0.1
 * @see Jwt
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7519#section-5">JWT JOSE Header</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7515#section-4">JWS JOSE Header</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7516#section-4">JWE JOSE Header</a>
 * @deprecated See <a target="_blank" href="https://github.com/spring-projects/spring-authorization-server/issues/596">gh-596</a>
 */
@Deprecated
public final class JoseHeader {
	private final Map<String, Object> headers;

	private JoseHeader(Map<String, Object> headers) {
		this.headers = Collections.unmodifiableMap(new HashMap<>(headers));
	}

	/**
	 * Returns the {@link JwaAlgorithm JWA algorithm} used to digitally sign the JWS or encrypt the JWE.
	 *
	 * @return the {@link JwaAlgorithm}
	 */
	@SuppressWarnings("unchecked")
	public <T extends JwaAlgorithm> T getAlgorithm() {
		return (T) getHeader(JoseHeaderNames.ALG);
	}

	/**
	 * Returns the JWK Set URL that refers to the resource of a set of JSON-encoded public keys,
	 * one of which corresponds to the key used to digitally sign the JWS or encrypt the JWE.
	 *
	 * @return the JWK Set URL
	 */
	public URL getJwkSetUrl() {
		return getHeader(JoseHeaderNames.JKU);
	}

	/**
	 * Returns the JSON Web Key which is the public key that corresponds to the key
	 * used to digitally sign the JWS or encrypt the JWE.
	 *
	 * @return the JSON Web Key
	 */
	public Map<String, Object> getJwk() {
		return getHeader(JoseHeaderNames.JWK);
	}

	/**
	 * Returns the key ID that is a hint indicating which key was used to secure the JWS or JWE.
	 *
	 * @return the key ID
	 */
	public String getKeyId() {
		return getHeader(JoseHeaderNames.KID);
	}

	/**
	 * Returns the X.509 URL that refers to the resource for the X.509 public key certificate
	 * or certificate chain corresponding to the key used to digitally sign the JWS or encrypt the JWE.
	 *
	 * @return the X.509 URL
	 */
	public URL getX509Url() {
		return getHeader(JoseHeaderNames.X5U);
	}

	/**
	 * Returns the X.509 certificate chain that contains the X.509 public key certificate
	 * or certificate chain corresponding to the key used to digitally sign the JWS or
	 * encrypt the JWE. The certificate or certificate chain is represented as a
	 * {@code List} of certificate value {@code String}s. Each {@code String} in the
	 * {@code List} is a Base64-encoded DER PKIX certificate value.
	 *
	 * @return the X.509 certificate chain
	 */
	public List<String> getX509CertificateChain() {
		return getHeader(JoseHeaderNames.X5C);
	}

	/**
	 * Returns the X.509 certificate SHA-1 thumbprint that is a base64url-encoded SHA-1 thumbprint (a.k.a. digest)
	 * of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS or encrypt the JWE.
	 *
	 * @return the X.509 certificate SHA-1 thumbprint
	 */
	public String getX509SHA1Thumbprint() {
		return getHeader(JoseHeaderNames.X5T);
	}

	/**
	 * Returns the X.509 certificate SHA-256 thumbprint that is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
	 * of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS or encrypt the JWE.
	 *
	 * @return the X.509 certificate SHA-256 thumbprint
	 */
	public String getX509SHA256Thumbprint() {
		return getHeader(JoseHeaderNames.X5T_S256);
	}

	/**
	 * Returns the type header that declares the media type of the JWS/JWE.
	 *
	 * @return the type header
	 */
	public String getType() {
		return getHeader(JoseHeaderNames.TYP);
	}

	/**
	 * Returns the content type header that declares the media type of the secured content (the payload).
	 *
	 * @return the content type header
	 */
	public String getContentType() {
		return getHeader(JoseHeaderNames.CTY);
	}

	/**
	 * Returns the critical headers that indicates which extensions to the JWS/JWE/JWA specifications
	 * are being used that MUST be understood and processed.
	 *
	 * @return the critical headers
	 */
	public Set<String> getCritical() {
		return getHeader(JoseHeaderNames.CRIT);
	}

	/**
	 * Returns the headers.
	 *
	 * @return the headers
	 */
	public Map<String, Object> getHeaders() {
		return this.headers;
	}

	/**
	 * Returns the header value.
	 *
	 * @param name the header name
	 * @param <T> the type of the header value
	 * @return the header value
	 */
	@SuppressWarnings("unchecked")
	public <T> T getHeader(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) getHeaders().get(name);
	}

	/**
	 * Returns a new {@link Builder}.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@link JwaAlgorithm}.
	 *
	 * @param jwaAlgorithm the {@link JwaAlgorithm}
	 * @return the {@link Builder}
	 */
	public static Builder withAlgorithm(JwaAlgorithm jwaAlgorithm) {
		return new Builder(jwaAlgorithm);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@code headers}.
	 *
	 * @param headers the headers
	 * @return the {@link Builder}
	 */
	public static Builder from(JoseHeader headers) {
		return new Builder(headers);
	}

	/**
	 * A builder for {@link JoseHeader}.
	 */
	public static final class Builder {
		private final Map<String, Object> headers = new HashMap<>();

		private Builder() {
		}

		private Builder(JwaAlgorithm jwaAlgorithm) {
			algorithm(jwaAlgorithm);
		}

		private Builder(JoseHeader headers) {
			Assert.notNull(headers, "headers cannot be null");
			this.headers.putAll(headers.getHeaders());
		}

		/**
		 * Sets the {@link JwaAlgorithm JWA algorithm} used to digitally sign the JWS or encrypt the JWE.
		 *
		 * @param jwaAlgorithm the {@link JwaAlgorithm}
		 * @return the {@link Builder}
		 */
		public Builder algorithm(JwaAlgorithm jwaAlgorithm) {
			Assert.notNull(jwaAlgorithm, "jwaAlgorithm cannot be null");
			return header(JoseHeaderNames.ALG, jwaAlgorithm);
		}

		/**
		 * Sets the JWK Set URL that refers to the resource of a set of JSON-encoded public keys,
		 * one of which corresponds to the key used to digitally sign the JWS or encrypt the JWE.
		 *
		 * @param jwkSetUrl the JWK Set URL
		 * @return the {@link Builder}
		 */
		public Builder jwkSetUrl(String jwkSetUrl) {
			return header(JoseHeaderNames.JKU, convertAsURL(JoseHeaderNames.JKU, jwkSetUrl));
		}

		/**
		 * Sets the JSON Web Key which is the public key that corresponds to the key
		 * used to digitally sign the JWS or encrypt the JWE.
		 *
		 * @param jwk the JSON Web Key
		 * @return the {@link Builder}
		 */
		public Builder jwk(Map<String, Object> jwk) {
			return header(JoseHeaderNames.JWK, jwk);
		}

		/**
		 * Sets the key ID that is a hint indicating which key was used to secure the JWS or JWE.
		 *
		 * @param keyId the key ID
		 * @return the {@link Builder}
		 */
		public Builder keyId(String keyId) {
			return header(JoseHeaderNames.KID, keyId);
		}

		/**
		 * Sets the X.509 URL that refers to the resource for the X.509 public key certificate
		 * or certificate chain corresponding to the key used to digitally sign the JWS or encrypt the JWE.
		 *
		 * @param x509Url the X.509 URL
		 * @return the {@link Builder}
		 */
		public Builder x509Url(String x509Url) {
			return header(JoseHeaderNames.X5U, convertAsURL(JoseHeaderNames.X5U, x509Url));
		}

		/**
		 * Sets the X.509 certificate chain that contains the X.509 public key certificate
		 * or certificate chain corresponding to the key used to digitally sign the JWS or
		 * encrypt the JWE. The certificate or certificate chain is represented as a
		 * {@code List} of certificate value {@code String}s. Each {@code String} in the
		 * {@code List} is a Base64-encoded DER PKIX certificate value.
		 *
		 * @param x509CertificateChain the X.509 certificate chain
		 * @return the {@link Builder}
		 */
		public Builder x509CertificateChain(List<String> x509CertificateChain) {
			return header(JoseHeaderNames.X5C, x509CertificateChain);
		}

		/**
		 * Sets the X.509 certificate SHA-1 thumbprint that is a base64url-encoded SHA-1 thumbprint (a.k.a. digest)
		 * of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS or encrypt the JWE.
		 *
		 * @param x509SHA1Thumbprint the X.509 certificate SHA-1 thumbprint
		 * @return the {@link Builder}
		 */
		public Builder x509SHA1Thumbprint(String x509SHA1Thumbprint) {
			return header(JoseHeaderNames.X5T, x509SHA1Thumbprint);
		}

		/**
		 * Sets the X.509 certificate SHA-256 thumbprint that is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
		 * of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS or encrypt the JWE.
		 *
		 * @param x509SHA256Thumbprint the X.509 certificate SHA-256 thumbprint
		 * @return the {@link Builder}
		 */
		public Builder x509SHA256Thumbprint(String x509SHA256Thumbprint) {
			return header(JoseHeaderNames.X5T_S256, x509SHA256Thumbprint);
		}

		/**
		 * Sets the type header that declares the media type of the JWS/JWE.
		 *
		 * @param type the type header
		 * @return the {@link Builder}
		 */
		public Builder type(String type) {
			return header(JoseHeaderNames.TYP, type);
		}

		/**
		 * Sets the content type header that declares the media type of the secured content (the payload).
		 *
		 * @param contentType the content type header
		 * @return the {@link Builder}
		 */
		public Builder contentType(String contentType) {
			return header(JoseHeaderNames.CTY, contentType);
		}

		/**
		 * Sets the critical headers that indicates which extensions to the JWS/JWE/JWA specifications
		 * are being used that MUST be understood and processed.
		 *
		 * @param headerNames the critical header names
		 * @return the {@link Builder}
		 */
		public Builder critical(Set<String> headerNames) {
			return header(JoseHeaderNames.CRIT, headerNames);
		}

		/**
		 * Sets the header.
		 *
		 * @param name the header name
		 * @param value the header value
		 * @return the {@link Builder}
		 */
		public Builder header(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.headers.put(name, value);
			return this;
		}

		/**
		 * A {@code Consumer} to be provided access to the headers
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param headersConsumer a {@code Consumer} of the headers
		 * @return the {@link Builder}
		 */
		public Builder headers(Consumer<Map<String, Object>> headersConsumer) {
			headersConsumer.accept(this.headers);
			return this;
		}

		/**
		 * Builds a new {@link JoseHeader}.
		 *
		 * @return a {@link JoseHeader}
		 */
		public JoseHeader build() {
			Assert.notEmpty(this.headers, "headers cannot be empty");
			return new JoseHeader(this.headers);
		}

		private static URL convertAsURL(String header, String value) {
			URL convertedValue = ClaimConversionService.getSharedInstance().convert(value, URL.class);
			Assert.isTrue(convertedValue != null,
					() -> "Unable to convert header '" + header + "' of type '" + value.getClass() + "' to URL.");
			return convertedValue;
		}

	}
}
