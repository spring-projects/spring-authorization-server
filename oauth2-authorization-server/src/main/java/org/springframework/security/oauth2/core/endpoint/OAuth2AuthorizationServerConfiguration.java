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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.oauth2.core.AbstractOAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationServerMetadataClaimAccessor;
import org.springframework.security.oauth2.core.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Map;

/**
 * A representation of an OAuth 2.0 Authorization Server Configuration response,
 * which is returned form an OAuth 2.0 Authorization Server's Configuration Endpoint,
 * and contains a set of claims about the Authorization Server's configuration.
 * The claims are defined by the OAuth 2.0 Authorization Server Metadata
 * specification (RFC 8414).
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.1
 * @see AbstractOAuth2AuthorizationServerConfiguration
 * @see OAuth2AuthorizationServerMetadataClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-3.2">3.2. Authorization Server Metadata Response</a>
 */
public final class OAuth2AuthorizationServerConfiguration extends AbstractOAuth2AuthorizationServerConfiguration
		implements OAuth2AuthorizationServerMetadataClaimAccessor, Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

	private OAuth2AuthorizationServerConfiguration(Map<String, Object> claims) {
		super(claims);
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
	 * @return the {@link Builder}
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		return new Builder()
				.claims(c -> c.putAll(claims));
	}

	/**
	 * Helps configure an {@link OAuth2AuthorizationServerConfiguration}.
	 */
	public static class Builder
			extends AbstractOAuth2AuthorizationServerConfiguration.AbstractBuilder<OAuth2AuthorizationServerConfiguration, Builder> {
		private Builder() {
		}

		/**
		 * Validate the claims and build the {@link OAuth2AuthorizationServerConfiguration}.
		 * <p>
		 * The following claims are REQUIRED:
		 * {@code issuer}, {@code authorization_endpoint}, {@code token_endpoint},
		 * {@code jwks_uri} and {@code response_types_supported}.
		 *
		 * @return the {@link OAuth2AuthorizationServerConfiguration}
		 */
		public OAuth2AuthorizationServerConfiguration build() {
			validateCommonClaims();
			removeEmptyClaims();
			return new OAuth2AuthorizationServerConfiguration(this.claims);
		}

	}
}
