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
package org.springframework.security.oauth2.core.oidc;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.Version;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A representation of an OpenID Client Registration Request and Response,
 * which contains a set of claims defined by the
 * OpenID Connect Registration 1.0 specification.
 *
 * @author Ovidiu Popa
 * @since 0.1.1
 * @see OidcClientMetadataClaimAccessor
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">3.1.  Client Registration Request</a>
 */
public final class OidcClientRegistration implements OidcClientMetadataClaimAccessor, Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final Map<String, Object> claims;

	private OidcClientRegistration(Map<String, Object> claims) {
		this.claims = Collections.unmodifiableMap(claims);
	}

	/**
	 * Returns the OpenID Client Registration metadata.
	 *
	 * @return a {@code Map} of the metadata values
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Constructs a new {@link OidcClientRegistration.Builder} with empty claims.
	 *
	 * @return the {@link OidcClientRegistration.Builder}
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

	public static class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Add this Redirect URI to the collection of {@code redirect_uris} in the resulting
		 * {@link OidcClientRegistration}, REQUIRED.
		 *
		 * @param redirectUri the OAuth 2.0 {@code redirect_uri} value that client supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder redirectUri(String redirectUri) {
			addClaimToClaimList(OidcClientMetadataClaimNames.REDIRECT_URIS, redirectUri);
			return this;
		}

		/**
		 * A {@code Consumer} of the Redirect URI(s) allowing the ability to add, replace, or remove.
		 *
		 * @param redirectUriConsumer a {@code Consumer} of the Redirect URI(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder redirectUris(Consumer<List<String>> redirectUriConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.REDIRECT_URIS, redirectUriConsumer);
			return this;
		}

		/**
		 * Add this Response Type to the collection of {@code response_types} in the resulting
		 * {@link OidcClientRegistration}, OPTIONAL.
		 *
		 * @param responseType the OAuth 2.0 {@code response_type} value that client supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseType(String responseType) {
			addClaimToClaimList(OidcClientMetadataClaimNames.RESPONSE_TYPES, responseType);
			return this;
		}

		/**
		 * Add {@code Consumer}  of {@code response_types} allowing the ability to add, replace, or remove
		 * {@link OidcClientRegistration}, OPTIONAL.
		 *
		 * @param responseType the OAuth 2.0 {@code response_type} value that client supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder responseTypes(Consumer<List<String>>  responseType) {
			acceptClaimValues(OidcClientMetadataClaimNames.RESPONSE_TYPES, responseType);
			return this;
		}

		/**
		 * Sets {@code client_name} claim in the resulting
		 * {@link OidcClientRegistration}, OPTIONAL.
		 *
		 * @param clientName the OAuth 2.0 {@code client_name} of the registered client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientName(String clientName) {
			return claim(OidcClientMetadataClaimNames.CLIENT_NAME, clientName);
		}

		/**
		 * Sets {@code client_id} claim in the resulting
		 * {@link OidcClientRegistration}.
		 *
		 * @param clientId the OAuth 2.0 {@code client_id} of the registered client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientId(String clientId) {
			return claim(OidcClientMetadataClaimNames.CLIENT_ID, clientId);
		}

		/**
		 * Sets {@code client_id_issued_at} claim in the resulting
		 * {@link OidcClientRegistration}.
		 *
		 * @param clientIssuedAt the timestamp {@code client_id_issued_at} when the client was issued
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientIdIssuedAt(Instant clientIssuedAt) {
			return claim(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, clientIssuedAt);
		}

		/**
		 * Sets {@code client_secret} claim in the resulting
		 * {@link OidcClientRegistration}.
		 *
		 * @param clientSecret the {@code client_secret} of the registered client
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientSecret(String clientSecret) {
			return claim(OidcClientMetadataClaimNames.CLIENT_SECRET, clientSecret);
		}

		/**
		 * Sets {@code client_secret_expires_at} claim in the resulting
		 * {@link OidcClientRegistration}.
		 *
		 * @param clientSecretExpiresAt the timestamp {@code client_secret_expires_at} when the client_secret expires
		 * @return the {@link Builder} for further configuration
		 */
		public Builder clientSecretExpiresAt(Instant clientSecretExpiresAt) {
			return claim(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
		}

		/**
		 * Add this Grant Type to the collection of {@code grant_types_supported} in the resulting
		 * {@link OidcClientRegistration}, OPTIONAL.
		 *
		 * @param grantType the OAuth 2.0 {@code grant_type} value that client supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantType(String grantType) {
			addClaimToClaimList(OidcClientMetadataClaimNames.GRANT_TYPES, grantType);
			return this;
		}

		/**
		 * A {@code Consumer} of the Grant Type(s) allowing the ability to add, replace, or remove.
		 *
		 * @param grantTypesConsumer a {@code Consumer} of the Grant Type(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder grantTypes(Consumer<List<String>> grantTypesConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.GRANT_TYPES, grantTypesConsumer);
			return this;
		}

		/**
		 * Add this Scope to the collection of {@code scopes_supported} in the resulting
		 * {@link OidcClientRegistration}, RECOMMENDED.
		 *
		 * @param scope the OAuth 2.0 {@code scope} value that client supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scope(String scope) {
			claim(OidcClientMetadataClaimNames.SCOPE, scope);
			return this;
		}

		/**
		 * Add {@code Consumer}  of {@code scopes} allowing the ability to add, replace, or remove
		 * {@link OidcClientRegistration}, RECOMMENDED.
		 *
		 * @param scopesConsumer the OAuth 2.0 {@code scope} value that client supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder scopes(Consumer<List<String>>  scopesConsumer) {
			acceptClaimValues(OidcClientMetadataClaimNames.SCOPE, scopesConsumer);
			return this;
		}

		/**
		 * Add this Token endpoint authentication method to the collection of {@code token_endpoint_auth_method} in the resulting
		 * {@link OidcClientRegistration}, OPTIONAL.
		 *
		 * @param tokenEndpointAuthenticationMethod the OAuth 2.0 {@code token_endpoint_auth_method} value that client supports
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenEndpointAuthenticationMethod(String tokenEndpointAuthenticationMethod) {
			claim(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, tokenEndpointAuthenticationMethod);
			return this;
		}

		/**
		 * Add this claim in the resulting {@link OidcClientRegistration}.
		 *
		 * @param name  the claim name
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

		public OidcClientRegistration build() {
			this.claims.computeIfAbsent(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD,
					k -> ClientAuthenticationMethod.BASIC.getValue());
			// If omitted, the default is that the Client will use only the authorization_code Grant Type.
			this.claims.computeIfAbsent(OidcClientMetadataClaimNames.GRANT_TYPES,
					k -> Collections.singletonList(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
			//If omitted, the default is that the Client will use only the code Response Type.
			this.claims.computeIfAbsent(OidcClientMetadataClaimNames.RESPONSE_TYPES,
					k -> Collections.singletonList(OAuth2AuthorizationResponseType.CODE.getValue()));
			validateRedirectUris();
			validateReponseTypesClaim();
			validateGrantTypesClaim();
			return new OidcClientRegistration(this.claims);
		}

		private void validateRedirectUris() {
			// redirect_uris is required
			Assert.notNull(this.claims.get(OidcClientMetadataClaimNames.REDIRECT_URIS), "redirect_uris cannot be null");
			Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.REDIRECT_URIS), "redirect_uris must be of type list");
			Assert.notEmpty((List<?>) this.claims.get(OidcClientMetadataClaimNames.REDIRECT_URIS), "redirect_uris must not be empty");
			((List<?>) this.claims.get(OidcClientMetadataClaimNames.REDIRECT_URIS)).forEach(
					url -> validateURL(url, "redirect_uri must be a valid URL")
			);
		}

		private void validateGrantTypesClaim() {
			Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.GRANT_TYPES), "grant_types must be of type List");
			List<?> grantTypes = (List<?>) this.claims.get(OidcClientMetadataClaimNames.GRANT_TYPES);
			// If empty, the default is that the Client will use only the authorization_code Grant Type.
			if (grantTypes.isEmpty()) {
				this.claims.put(OidcClientMetadataClaimNames.GRANT_TYPES,
						Collections.singletonList(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
			}
		}

		private void validateReponseTypesClaim() {
			Assert.isInstanceOf(List.class, this.claims.get(OidcClientMetadataClaimNames.RESPONSE_TYPES), "response_types must be of type List");
			List<?> responseTypes = (List<?>) this.claims.get(OidcClientMetadataClaimNames.RESPONSE_TYPES);
			//If empty, the default is that the Client will use only the code Response Type.
			if (responseTypes.isEmpty()) {
				this.claims.put(OidcClientMetadataClaimNames.RESPONSE_TYPES, Collections.singletonList(OAuth2AuthorizationResponseType.CODE.getValue()));
			}
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
