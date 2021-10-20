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
package org.springframework.security.oauth2.server.authorization.config;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

/**
 * The names for all the configuration settings.
 *
 * @author Joe Grandja
 * @since 0.2.0
 */
public final class ConfigurationSettingNames {
	private static final String SETTINGS_NAMESPACE = "settings.";

	private ConfigurationSettingNames() {
	}

	/**
	 * The names for client configuration settings.
	 */
	public static final class Client {
		private static final String CLIENT_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("client.");

		/**
		 * Set to {@code true} if the client is required to provide a proof key challenge and verifier
		 * when performing the Authorization Code Grant flow.
		 */
		public static final String REQUIRE_PROOF_KEY = CLIENT_SETTINGS_NAMESPACE.concat("require-proof-key");

		/**
		 * Set to {@code true} if authorization consent is required when the client requests access.
		 * This applies to all interactive flows (e.g. {@code authorization_code} and {@code device_code}).
		 */
		public static final String REQUIRE_AUTHORIZATION_CONSENT = CLIENT_SETTINGS_NAMESPACE.concat("require-authorization-consent");

		private Client() {
		}

	}

	/**
	 * The names for provider configuration settings.
	 */
	public static final class Provider {
		private static final String PROVIDER_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("provider.");

		/**
		 * Set the URL the Provider uses as its Issuer Identifier.
		 */
		public static final String ISSUER = PROVIDER_SETTINGS_NAMESPACE.concat("issuer");

		/**
		 * Set the Provider's OAuth 2.0 Authorization endpoint.
		 */
		public static final String AUTHORIZATION_ENDPOINT = PROVIDER_SETTINGS_NAMESPACE.concat("authorization-endpoint");

		/**
		 * Set the Provider's OAuth 2.0 Token endpoint.
		 */
		public static final String TOKEN_ENDPOINT = PROVIDER_SETTINGS_NAMESPACE.concat("token-endpoint");

		/**
		 * Set the Provider's JWK Set endpoint.
		 */
		public static final String JWK_SET_ENDPOINT = PROVIDER_SETTINGS_NAMESPACE.concat("jwk-set-endpoint");

		/**
		 * Set the Provider's OAuth 2.0 Token Revocation endpoint.
		 */
		public static final String TOKEN_REVOCATION_ENDPOINT = PROVIDER_SETTINGS_NAMESPACE.concat("token-revocation-endpoint");

		/**
		 * Set the Provider's OAuth 2.0 Token Introspection endpoint.
		 */
		public static final String TOKEN_INTROSPECTION_ENDPOINT = PROVIDER_SETTINGS_NAMESPACE.concat("token-introspection-endpoint");

		/**
		 * Set the Provider's OpenID Connect 1.0 Client Registration endpoint.
		 */
		public static final String OIDC_CLIENT_REGISTRATION_ENDPOINT = PROVIDER_SETTINGS_NAMESPACE.concat("oidc-client-registration-endpoint");

		/**
		 * Set the Provider's OpenID Connect 1.0 UserInfo endpoint.
		 */
		public static final String OIDC_USER_INFO_ENDPOINT = PROVIDER_SETTINGS_NAMESPACE.concat("oidc-user-info-endpoint");

		private Provider() {
		}

	}

	/**
	 * The names for token configuration settings.
	 */
	public static final class Token {
		private static final String TOKEN_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("token.");

		/**
		 * Set the time-to-live for an access token.
		 */
		public static final String ACCESS_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE.concat("access-token-time-to-live");

		/**
		 * Set to {@code true} if refresh tokens are reused when returning the access token response,
		 * or {@code false} if a new refresh token is issued.
		 */
		public static final String REUSE_REFRESH_TOKENS = TOKEN_SETTINGS_NAMESPACE.concat("reuse-refresh-tokens");

		/**
		 * Set the time-to-live for a refresh token.
		 */
		public static final String REFRESH_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE.concat("refresh-token-time-to-live");

		/**
		 * Set the {@link SignatureAlgorithm JWS} algorithm for signing the {@link OidcIdToken ID Token}.
		 */
		public static final String ID_TOKEN_SIGNATURE_ALGORITHM = TOKEN_SETTINGS_NAMESPACE.concat("id-token-signature-algorithm");

		private Token() {
		}

	}

}
