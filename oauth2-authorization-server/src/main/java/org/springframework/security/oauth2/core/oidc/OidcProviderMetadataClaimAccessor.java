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


import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URL;
import java.util.List;

/**
 * A {@link ClaimAccessor} for the "claims" that can be returned
 * in the OpenID Provider Configuration Response.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see ClaimAccessor
 * @see OidcProviderMetadataClaimNames
 * @see OidcProviderConfiguration
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">3. OpenID Provider Metadata</a>
 */
public interface OidcProviderMetadataClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the {@code URL} the OpenID Provider asserts as its Issuer Identifier {@code (issuer)}.
	 *
	 * @return the {@code URL} the OpenID Provider asserts as its Issuer Identifier
	 */
	default URL getIssuer() {
		return getClaimAsURL(OidcProviderMetadataClaimNames.ISSUER);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Authorization Endpoint {@code (authorization_endpoint)}.
	 *
	 * @return the {@code URL} of the OAuth 2.0 Authorization Endpoint
	 */
	default URL getAuthorizationEndpoint() {
		return getClaimAsURL(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT);
	}

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Token Endpoint {@code (token_endpoint)}.
	 *
	 * @return the {@code URL} of the OAuth 2.0 Token Endpoint
	 */
	default URL getTokenEndpoint() {
		return getClaimAsURL(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT);
	}

	/**
	 * Returns the client authentication methods supported by the OAuth 2.0 Token Endpoint {@code (token_endpoint_auth_methods_supported)}.
	 *
	 * @return the client authentication methods supported by the OAuth 2.0 Token Endpoint
	 */
	default List<String> getTokenEndpointAuthenticationMethods() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED);
	}

	/**
	 * Returns the {@code URL} of the JSON Web Key Set {@code (jwks_uri)}.
	 *
	 * @return the {@code URL} of the JSON Web Key Set
	 */
	default URL getJwkSetUri() {
		return getClaimAsURL(OidcProviderMetadataClaimNames.JWKS_URI);
	}

	/**
	 * Returns the OAuth 2.0 {@code response_type} values supported {@code (response_types_supported)}.
	 *
	 * @return the OAuth 2.0 {@code response_type} values supported
	 */
	default List<String> getResponseTypes() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
	}

	/**
	 * Returns the OAuth 2.0 {@code grant_type} values supported {@code (grant_types_supported)}.
	 *
	 * @return the OAuth 2.0 {@code grant_type} values supported
	 */
	default List<String> getGrantTypes() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED);
	}

	/**
	 * Returns the Subject Identifier types supported {@code (subject_types_supported)}.
	 *
	 * @return the Subject Identifier types supported
	 */
	default List<String> getSubjectTypes() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
	}

	/**
	 * Returns the OAuth 2.0 {@code scope} values supported {@code (scopes_supported)}.
	 *
	 * @return the OAuth 2.0 {@code scope} values supported
	 */
	default List<String> getScopes() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED);
	}

	/**
	 * Returns the {@link JwsAlgorithm JWS} signing algorithms supported for the {@link OidcIdToken ID Token}
	 * to encode the claims in a {@link Jwt} {@code (id_token_signing_alg_values_supported)}.
	 *
	 * @return the {@link JwsAlgorithm JWS} signing algorithms supported for the {@link OidcIdToken ID Token}
	 */
	default List<String> getIdTokenSigningAlgorithms() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED);
	}

}
