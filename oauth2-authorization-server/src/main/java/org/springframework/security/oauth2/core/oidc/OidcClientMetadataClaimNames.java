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

/**
 * The names of the "claims" defined by OpenID Client Registration 1.0 that can be returned
 * in the OpenID Client Registration Response.
 *
 * @author Ovidiu Popa
 * @since 0.1.1
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">2. Client Metadata</a>
 */
public interface OidcClientMetadataClaimNames {

	//request
	/**
	 * {@code redirect_uris} - the redirect URI(s) that the client may use in redirect-based flows
	 */
	String REDIRECT_URIS = "redirect_uris";

	/**
	 * {@code response_types} - the OAuth 2.0 {@code response_type} values that the client may use
	 */
	String RESPONSE_TYPES = "response_types";

	/**
	 * {@code grant_types} - the OAuth 2.0 authorization {@code grant_types} that the client may use
	 */
	String GRANT_TYPES = "grant_types";

	/**
	 * {@code client_name} - the {@code client_name}
	 */
	String CLIENT_NAME = "client_name";

	/**
	 * {@code scope} - the scope(s) that the client may use
	 */
	String SCOPE = "scope";

	/**
	 * {@code token_endpoint_auth_method} - the {@link org.springframework.security.oauth2.core.ClientAuthenticationMethod authentication method} that the client may use.
	 */
	String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";

	//response
	/**
	 * {@code client_id} - the {@code client_id}
	 */
	String CLIENT_ID = "client_id";

	/**
	 * {@code client_secret} - the {@code client_secret}
	 */
	String CLIENT_SECRET = "client_secret";

	/**
	 * {@code client_id_issued_at} - the timestamp when the client id was issued
	 */
	String CLIENT_ID_ISSUED_AT = "client_id_issued_at";

	/**
	 * {@code client_secret_expires_at} - the timestamp when the client secret expires
	 */
	String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";
}
