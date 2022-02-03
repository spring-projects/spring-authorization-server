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
package org.springframework.security.oauth2.core.oidc;

import org.springframework.security.oauth2.core.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;

/**
 * The names of the "claims" defined by OpenID Connect Discovery 1.0 that can be returned
 * in the OpenID Provider Configuration Response.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see OAuth2AuthorizationServerMetadataClaimNames
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">3. OpenID Provider Metadata</a>
 */
public interface OidcProviderMetadataClaimNames extends OAuth2AuthorizationServerMetadataClaimNames {

	/**
	 * {@code subject_types_supported} - the Subject Identifier types supported
	 */
	String SUBJECT_TYPES_SUPPORTED = "subject_types_supported";

	/**
	 * {@code id_token_signing_alg_values_supported} - the {@link JwsAlgorithm JWS} signing algorithms supported for the {@link OidcIdToken ID Token}
	 */
	String ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported";

	/**
	 * {@code userinfo_endpoint} - the {@code URL} of the OpenID Connect 1.0 UserInfo Endpoint
	 * @since 0.2.2
	 */
	String USER_INFO_ENDPOINT = "userinfo_endpoint";

}
