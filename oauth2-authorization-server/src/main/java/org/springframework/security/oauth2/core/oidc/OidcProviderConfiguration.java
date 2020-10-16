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

import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
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
public class OidcProviderConfiguration implements OidcProviderMetadataClaimAccessor, Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

	private final Map<String, Object> claims;

	private OidcProviderConfiguration(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
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
	 * Constructs a new empty {@link Builder}.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder withClaims() {
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
	 *
	 * @author Daniel Garnier-Moiroux
	 * @since 0.1.0
	 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect Discovery 1.0</a>
	 * for required claims
	 */
	public static final class Builder {
		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Use this {@code issuer} in the resulting {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param issuer the issuer URI
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
		 * Use this {@code jwks_uri} in the resulting {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param jwksUri the URL of the OpenID Provider's JSON Web Key Set document
		 * @return the {@link Builder} for further configuration
		 */
		public Builder jwksUri(String jwksUri) {
			return claim(OidcProviderMetadataClaimNames.JWKS_URI, jwksUri);
		}

		/**
		 * Add this Response Type to the collection of {@code response_types_supported} in the resulting
		 * {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param responseType the OAuth 2.0 {@code response_type} values that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseType(String responseType) {
			addClaimToClaimSet(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, responseType);
			return this;
		}

		/**
		 * A {@code Consumer} of the Response Type(s) allowing the ability to add, replace, or remove.
		 *
		 * @param responseTypesConsumer a {@code Consumer} of the Response Type(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseTypes(Consumer<Set<String>> responseTypesConsumer) {
			applyToClaim(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, responseTypesConsumer);
			return this;
		}

		/**
		 * Add this Subject Type to the collection of {@code subject_types_supported} in the resulting
		 * {@link OidcProviderConfiguration}, REQUIRED.
		 *
		 * @param subjectType the Subject Identifiers that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder subjectType(String subjectType) {
			addClaimToClaimSet(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, subjectType);
			return this;
		}

		/**
		 * A {@code Consumer} of the Subject Types(s) allowing the ability to add, replace, or remove.
		 *
		 * @param subjectTypesConsumer a {@code Consumer} of the Subject Types(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder subjectTypes(Consumer<Set<String>> subjectTypesConsumer) {
			applyToClaim(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, subjectTypesConsumer);
			return this;
		}

		/**
		 * Add this Scope to the collection of {@code scopes_supported} in the resulting
		 * {@link OidcProviderConfiguration}, RECOMMENDED.
		 *
		 * @param scope the OAuth 2.0 {@code scopes} values that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scope(String scope) {
			addClaimToClaimSet(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, scope);
			return this;
		}

		/**
		 * A {@code Consumer} of the Scopes(s) allowing the ability to add, replace, or remove.
		 *
		 * @param scopesConsumer a {@code Consumer} of the Scopes(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scopes(Consumer<Set<String>> scopesConsumer) {
			applyToClaim(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, scopesConsumer);
			return this;
		}

		/**
		 * Add this Grant Type to the collection of {@code grant_types_supported} in the resulting
		 * {@link OidcProviderConfiguration}, OPTIONAL.
		 *
		 * @param grantType the OAuth 2.0 {@code grant_type} values that the OpenID Provider supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantType(String grantType) {
			addClaimToClaimSet(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantType);
			return this;
		}

		/**
		 * A {@code Consumer} of the Grant Type(s) allowing the ability to add, replace, or remove.
		 *
		 * @param grantTypesConsumer a {@code Consumer} of the Grant Type(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantTypes(Consumer<Set<String>> grantTypesConsumer) {
			applyToClaim(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantTypesConsumer);
			return this;
		}

		/**
		 * Add this Authentication Method to the collection of {@code token_endpoint_auth_methods_supported}
		 * in the resulting {@link OidcProviderConfiguration}, OPTIONAL.
		 *
		 * @param authenticationMethod the OAuth 2.0 Authentication Method supported by the Token endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationMethod(String authenticationMethod) {
			addClaimToClaimSet(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethod);
			return this;
		}

		/**
		 * A {@code Consumer} of the Token Endpoint Authentication Method(s) allowing the ability to add, replace, or remove.
		 *
		 * @param authenticationMethodsConsumer a {@code Consumer} of the Token Endpoint Authentication Method(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationMethods(Consumer<Set<String>> authenticationMethodsConsumer) {
			applyToClaim(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethodsConsumer);
			return this;
		}

		/**
		 * Use this claim in the resulting {@link OidcProviderConfiguration}
		 *
		 * @param name The claim name
		 * @param value The claim value
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
		 * @param claimsConsumer the consumer
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Validate the claims and build the {@link OidcProviderConfiguration}. The following claims are REQUIRED:
		 * - issuer
		 * - authorization_endpoint
		 * - token_endpoint
		 * - jwks_uri
		 * - response_types_supported
		 * - subject_types_supported
		 *
		 * @return The constructed {@link OidcProviderConfiguration}
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
			Assert.notNull(this.claims.get(OidcProviderMetadataClaimNames.JWKS_URI), "jwkSetUri cannot be null");
			validateURL(this.claims.get(OidcProviderMetadataClaimNames.JWKS_URI), "jwkSetUri must be a valid URL");
			Assert.notEmpty((Set<?>) this.claims.get(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED), "subjectTypes cannot be empty");
			Assert.notEmpty((Set<?>) this.claims.get(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED), "responseTypes cannot be empty");
		}

		private void validateURL(Object url, String errorMessage) {
			if (url.getClass().isAssignableFrom(URL.class)) return;

			try {
				new URI(url.toString()).toURL();
			} catch (Exception e) {
				throw new IllegalArgumentException(errorMessage);
			}

		}

		@SuppressWarnings("unchecked")
		private void addClaimToClaimSet(String name, String value) {
			this.claims.putIfAbsent(name, new LinkedHashSet<String>());
			((Set<String>) this.claims.get(name)).add(value);
		}

		@SuppressWarnings("unchecked")
		private void applyToClaim(String name, Consumer<Set<String>> consumer) {
			this.claims.putIfAbsent(name, new LinkedHashSet<String>());
			Set<String> values = (Set<String>) this.claims.get(name);
			consumer.accept(values);
		}
	}
}
