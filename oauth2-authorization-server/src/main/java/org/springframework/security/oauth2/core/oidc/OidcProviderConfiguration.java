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
package org.springframework.security.oauth2.core.oidc;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.core.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A representation of an OpenID Provider Configuration Response,
 * which is returned from an Issuer's Discovery Endpoint,
 * and contains a set of claims about the OpenID Provider's configuration.
 * The claims are defined by the OpenID Connect Discovery 1.0 specification.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see OidcProviderMetadataClaimAccessor
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">4.2. OpenID Provider Configuration Response</a>
 */
public final class OidcProviderConfiguration implements OidcProviderMetadataClaimAccessor, Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final Map<String, Object> claims;

	private OidcProviderConfiguration(Map<String, Object> claims) {
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the OpenID Provider Configuration metadata.
	 *
	 * @return a {@code Map} of the metadata values
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Constructs a new {@link Builder} with empty claims.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Constructs a new {@link Builder} with the provided claims.
	 *
	 * @param claims the claims to initialize the builder
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		return new Builder()
				.claims(c -> c.putAll(claims));
	}

	/**
	 * Helps configure an {@link OidcProviderConfiguration}
	 */
	public static class Builder {
		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Use this {@code issuer} in the resulting {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param issuer the URL of the OpenID Provider's Issuer Identifier
		 * @return the {@link Builder} for further configuration
		 */
		public Builder issuer(String issuer) {
			return claim(OidcProviderMetadataClaimNames.ISSUER, issuer);
		}

		/**
		 * Use this {@code authorization_endpoint} in the resulting {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param authorizationEndpoint the URL of the OpenID Provider's OAuth 2.0 Authorization Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationEndpoint(String authorizationEndpoint) {
			return claim(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
		}

		/**
		 * Use this {@code token_endpoint} in the resulting {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param tokenEndpoint the URL of the OpenID Provider's OAuth 2.0 Token Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpoint(String tokenEndpoint) {
			return claim(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, tokenEndpoint);
		}

		/**
		 * Add this Authentication Method to the collection of {@code token_endpoint_auth_methods_supported}
		 * in the resulting {@link OidcProviderConfiguration}, OPTIONAL.
		 *
		 * @param authenticationMethod the OAuth 2.0 Authentication Method supported by the Token endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationMethod(String authenticationMethod) {
			addClaimToClaimList(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethod);
			return this;
		}

		/**
		 * A {@code Consumer} of the Token Endpoint Authentication Method(s) allowing the ability to add, replace, or remove.
		 *
		 * @param authenticationMethodsConsumer a {@code Consumer} of the Token Endpoint Authentication Method(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationMethods(Consumer<List<String>> authenticationMethodsConsumer) {
			acceptClaimValues(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethodsConsumer);
			return this;
		}

		/**
		 * Use this {@code jwks_uri} in the resulting {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param jwkSetUri the URL of the OpenID Provider's JSON Web Key Set document
		 * @return the {@link Builder} for further configuration
		 */
		public Builder jwkSetUri(String jwkSetUri) {
			return claim(OidcProviderMetadataClaimNames.JWKS_URI, jwkSetUri);
		}

		/**
		 * Add this Response Type to the collection of {@code response_types_supported} in the resulting
		 * {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param responseType the OAuth 2.0 {@code response_type} value that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseType(String responseType) {
			addClaimToClaimList(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, responseType);
			return this;
		}

		/**
		 * A {@code Consumer} of the Response Type(s) allowing the ability to add, replace, or remove.
		 *
		 * @param responseTypesConsumer a {@code Consumer} of the Response Type(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseTypes(Consumer<List<String>> responseTypesConsumer) {
			acceptClaimValues(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, responseTypesConsumer);
			return this;
		}

		/**
		 * Add this Grant Type to the collection of {@code grant_types_supported} in the resulting
		 * {@link OidcProviderConfiguration}, OPTIONAL.
		 *
		 * @param grantType the OAuth 2.0 {@code grant_type} value that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantType(String grantType) {
			addClaimToClaimList(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantType);
			return this;
		}

		/**
		 * A {@code Consumer} of the Grant Type(s) allowing the ability to add, replace, or remove.
		 *
		 * @param grantTypesConsumer a {@code Consumer} of the Grant Type(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantTypes(Consumer<List<String>> grantTypesConsumer) {
			acceptClaimValues(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantTypesConsumer);
			return this;
		}

		/**
		 * Add this Subject Type to the collection of {@code subject_types_supported} in the resulting
		 * {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param subjectType the Subject Type that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder subjectType(String subjectType) {
			addClaimToClaimList(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, subjectType);
			return this;
		}

		/**
		 * A {@code Consumer} of the Subject Types(s) allowing the ability to add, replace, or remove.
		 *
		 * @param subjectTypesConsumer a {@code Consumer} of the Subject Types(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder subjectTypes(Consumer<List<String>> subjectTypesConsumer) {
			acceptClaimValues(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, subjectTypesConsumer);
			return this;
		}

		/**
		 * Add this Scope to the collection of {@code scopes_supported} in the resulting
		 * {@link OidcProviderConfiguration}, RECOMMENDED.
		 *
		 * @param scope the OAuth 2.0 {@code scope} value that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scope(String scope) {
			addClaimToClaimList(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, scope);
			return this;
		}

		/**
		 * A {@code Consumer} of the Scopes(s) allowing the ability to add, replace, or remove.
		 *
		 * @param scopesConsumer a {@code Consumer} of the Scopes(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scopes(Consumer<List<String>> scopesConsumer) {
			acceptClaimValues(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, scopesConsumer);
			return this;
		}

		/**
		 * Add this {@link JwsAlgorithm JWS} signing algorithm to the collection of {@code id_token_signing_alg_values_supported}
		 * in the resulting {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param signingAlgorithm the {@link JwsAlgorithm JWS} signing algorithm supported for the {@link OidcIdToken ID Token}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder idTokenSigningAlgorithm(String signingAlgorithm) {
			addClaimToClaimList(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, signingAlgorithm);
			return this;
		}

		/**
		 * A {@code Consumer} of the {@link JwsAlgorithm JWS} signing algorithms for the {@link OidcIdToken ID Token}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param signingAlgorithmsConsumer a {@code Consumer} of the {@link JwsAlgorithm JWS} signing algorithms for the {@link OidcIdToken ID Token}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder idTokenSigningAlgorithms(Consumer<List<String>> signingAlgorithmsConsumer) {
			acceptClaimValues(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, signingAlgorithmsConsumer);
			return this;
		}

		/**
		 * Use this claim in the resulting {@link OidcProviderConfiguration}.
		 *
		 * @param name the claim name
		 * @param value the claim value
		 * @return the {@link Builder} for further configuration
		 */
		public Builder claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 *
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Validate the claims and build the {@link OidcProviderConfiguration}.
		 * <p>
		 * The following claims are REQUIRED:
		 * {@code issuer}, {@code authorization_endpoint}, {@code token_endpoint}, {@code jwks_uri},
		 * {@code response_types_supported} and {@code subject_types_supported}.
		 *
		 * @return the {@link OidcProviderConfiguration}
		 */
		public OidcProviderConfiguration build() {
			validateClaims();
			return new OidcProviderConfiguration(this.claims);
		}

		private void validateClaims() {
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.ISSUER), "issuer cannot be null");
			validateURL(this.claims.get(OidcProviderMetadataClaimNames.ISSUER), "issuer must be a valid URL");
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT), "authorizationEndpoint cannot be null");
			validateURL(this.claims.get(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT), "authorizationEndpoint must be a valid URL");
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT), "tokenEndpoint cannot be null");
			validateURL(this.claims.get(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT), "tokenEndpoint must be a valid URL");
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.JWKS_URI), "jwksUri cannot be null");
			validateURL(this.claims.get(OidcProviderMetadataClaimNames.JWKS_URI), "jwksUri must be a valid URL");
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED), "responseTypes cannot be null");
			Assert.isInstanceOf(List.class, this.claims.get(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED), "responseTypes must be of type List");
			Assert.notEmpty((List<?>) this.claims.get(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED), "responseTypes cannot be empty");
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED), "subjectTypes cannot be null");
			Assert.isInstanceOf(List.class, this.claims.get(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED), "subjectTypes must be of type List");
			Assert.notEmpty((List<?>) this.claims.get(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED), "subjectTypes cannot be empty");
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED), "idTokenSigningAlgorithms cannot be null");
			Assert.isInstanceOf(List.class, this.claims.get(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED), "idTokenSigningAlgorithms must be of type List");
			Assert.notEmpty((List<?>) this.claims.get(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED), "idTokenSigningAlgorithms cannot be empty");
		}

		private static void validateURL(Object url, String errorMessage) {
			if (URL.class.isAssignableFrom(url.getClass())) {
				return;
			}

			try {
				new URI(url.toString()).toURL();
			} catch (Exception ex) {
				throw new IllegalArgumentException(errorMessage, ex);
			}
		}

		@SuppressWarnings("unchecked")
		private void addClaimToClaimList(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.computeIfAbsent(name, k -> new LinkedList<String>());
			((List<String>) this.claims.get(name)).add(value);
		}

		@SuppressWarnings("unchecked")
		private void acceptClaimValues(String name, Consumer<List<String>> valuesConsumer) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(valuesConsumer, "valuesConsumer cannot be null");
			this.claims.computeIfAbsent(name, k -> new LinkedList<String>());
			List<String> values = (List<String>) this.claims.get(name);
			valuesConsumer.accept(values);
		}
	}
}
