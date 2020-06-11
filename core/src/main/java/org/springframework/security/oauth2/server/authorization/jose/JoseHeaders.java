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

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A representation of &quot;headers&quot; that may be contained
 * in the JSON object JOSE Header of a JSON Web Signature (JWS).
 *
 * @author Anoop Garlapati
 * @since 0.0.1
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-4">JOSE Header of JWS</a>
 */
public class JoseHeaders {

	private final Map<String, Object> headers;

	protected JoseHeaders(Map<String, Object> headers) {
		Assert.notEmpty(headers, "headers cannot be empty");
		this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
	}

	public SignatureAlgorithm getSignatureAlgorithm() {
		return SignatureAlgorithm.from(getHeaderAsString("alg"));
	}

	public MacAlgorithm getMacAlgorithm() {
		return MacAlgorithm.from(getHeaderAsString("alg"));
	}

	public String getType() {
		return getHeaderAsString("typ");
	}

	public Map<String, Object> getHeaders() {
		return this.headers;
	}

	public String getHeaderAsString(String header) {
		return !containsHeader(header) ? null :
				ClaimConversionService.getSharedInstance().convert(getHeaders().get(header), String.class);
	}

	@SuppressWarnings("unchecked")
	public List<String> getHeaderAsStringList(String header) {
		if (!containsHeader(header)) {
			return null;
		}
		final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		final TypeDescriptor targetDescriptor = TypeDescriptor.collection(
				List.class, TypeDescriptor.valueOf(String.class));
		Object headerValue = getHeaders().get(header);
		List<String> convertedValue = (List<String>) ClaimConversionService.getSharedInstance().convert(
				headerValue, sourceDescriptor, targetDescriptor);
		if (convertedValue == null) {
			throw new IllegalArgumentException("Unable to convert header '" + header +
					"' of type '" + headerValue.getClass() + "' to List.");
		}
		return convertedValue;
	}

	public URI getHeaderAsURI(String header) {
		if (!containsHeader(header)) {
			return null;
		}
		Object headerValue = getHeaders().get(header);
		URI convertedValue = ClaimConversionService.getSharedInstance().convert(headerValue, URI.class);
		if (convertedValue == null) {
			throw new IllegalArgumentException("Unable to convert header '" + header +
					"' of type '" + headerValue.getClass() + "' to URI.");
		}
		return convertedValue;
	}

	public Boolean getHeaderAsBoolean(String header) {
		return !containsHeader(header) ? null :
				ClaimConversionService.getSharedInstance().convert(getHeaders().get(header), Boolean.class);
	}

	private Boolean containsHeader(String header) {
		Assert.notNull(header, "header cannot be null");
		return getHeaders().containsKey(header);
	}

	public static class Builder {
		private Map<String, Object> headers = new LinkedHashMap<>();

		public Builder() {
		}

		public Builder(JoseHeaders joseHeaders) {
			Assert.notNull(joseHeaders, "joseHeaders cannot be null");
			this.headers = joseHeaders.headers;
		}

		public Builder header(String name, Object value) {
			Assert.notNull(name, "name cannot be null");
			this.headers.put(name, value);
			return this;
		}

		public Builder headers(Consumer<Map<String, Object>> headersConsumer) {
			Assert.notNull(headersConsumer, "headersConsumer cannot be null");
			headersConsumer.accept(this.headers);
			return this;
		}

		public Builder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.header("alg", signatureAlgorithm.getName());
			return this;
		}

		public Builder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			this.header("alg", macAlgorithm.getName());
			return this;
		}

		public Builder type(String type) {
			Assert.notNull(type, "type cannot be null");
			this.header("typ", type);
			return this;
		}

		public JoseHeaders build() {
			return new JoseHeaders(this.headers);
		}
	}
}
