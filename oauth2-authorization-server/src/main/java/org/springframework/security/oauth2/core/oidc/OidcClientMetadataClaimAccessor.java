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

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.time.Instant;
import java.util.List;

/**
 * A {@link ClaimAccessor} for the "claims" that can be returned
 * in the OpenID Client Registration Response.
 *
 * @author Ovidiu Popa
 * @since 0.1.1
 * @see ClaimAccessor
 * @see OidcClientMetadataClaimNames
 * @see OidcClientRegistration
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">2. Client Metadata</a>
 */
public interface OidcClientMetadataClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the redirect URI(s) that the client may use in redirect-based flows.
	 *
	 * @return the {@code List} of redirect URI(s)
	 */
	default List<String> getRedirectUris() {
		return getClaimAsStringList(OidcClientMetadataClaimNames.REDIRECT_URIS);
	}

	/**
	 * Returns the OAuth 2.0 {@code response_type} values that the client may use.
	 *
	 * @return the {@code List} of {@code response_type}
	 */
	default List<String> getResponseTypes() {
		return getClaimAsStringList(OidcClientMetadataClaimNames.RESPONSE_TYPES);
	}

	/**
	 * Returns the authorization {@code grant_types} that the client may use.
	 *
	 * @return the {@code List} of authorization {@code grant_types}
	 */
	default List<String> getGrantTypes() {
		return getClaimAsStringList(OidcClientMetadataClaimNames.GRANT_TYPES);
	}

	/**
	 * Returns the {@code client_name}.
	 *
	 * @return the {@code client_name}
	 */
	default String getClientName() {
		return getClaimAsString(OidcClientMetadataClaimNames.CLIENT_NAME);
	}

	/**
	 * Returns the scope(s) that the client may use.
	 *
	 * @return the scope(s)
	 */
	default String getScope() {
		return getClaimAsString(OidcClientMetadataClaimNames.SCOPE);
	}

	/**
	 * Returns the {@link ClientAuthenticationMethod authentication method} that the client may use.
	 *
	 * @return the {@link ClientAuthenticationMethod authentication method}
	 */
	default String getTokenEndpointAuthenticationMethod() {
		return getClaimAsString(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
	}

	/**
	 * Returns the {@code client_id}.
	 *
	 * @return the {@code client_id}
	 */
	default String getClientId() {
		return getClaimAsString(OidcClientMetadataClaimNames.CLIENT_ID);
	}

	/**
	 * Returns the {@code client_id_issued_at} timestamp.
	 *
	 * @return the {@code client_id_issued_at} timestamp
	 */
	default Instant getClientIdIssuedAt() {
		return getClaimAsInstant(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT);
	}

	/**
	 * Returns the {@code client_secret}.
	 *
	 * @return the {@code client_secret}
	 */
	default String getClientSecret() {
		return getClaimAsString(OidcClientMetadataClaimNames.CLIENT_SECRET);
	}

	/**
	 * Returns the {@code client_secret_expires_at} timestamp.
	 *
	 * @return the {@code client_secret_expires_at} timestamp
	 */
	default Instant getClientSecretExpiresAt() {
		return getClaimAsInstant(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
	}




}
