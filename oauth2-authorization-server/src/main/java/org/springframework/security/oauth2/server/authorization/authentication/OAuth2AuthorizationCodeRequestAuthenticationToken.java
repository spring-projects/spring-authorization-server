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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.Version;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * An {@link Authentication} implementation for the OAuth 2.0 Authorization Request (and Consent)
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private String authorizationUri;
	private String clientId;
	private Authentication principal;
	private String redirectUri;
	private Set<String> scopes;
	private String state;
	private Map<String, Object> additionalParameters;
	private boolean consentRequired;
	private boolean consent;
	private OAuth2AuthorizationCode authorizationCode;

	private OAuth2AuthorizationCodeRequestAuthenticationToken() {
		super(Collections.emptyList());
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the authorization URI.
	 *
	 * @return the authorization URI
	 */
	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	/**
	 * Returns the client identifier.
	 *
	 * @return the client identifier
	 */
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Returns the redirect uri.
	 *
	 * @return the redirect uri
	 */
	@Nullable
	public String getRedirectUri() {
		return this.redirectUri;
	}

	/**
	 * Returns the requested (or authorized) scope(s).
	 *
	 * @return the requested (or authorized) scope(s), or an empty {@code Set} if not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the state.
	 *
	 * @return the state
	 */
	@Nullable
	public String getState() {
		return this.state;
	}

	/**
	 * Returns the additional parameters.
	 *
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns {@code true} if authorization consent is required, {@code false} otherwise.
	 *
	 * @return {@code true} if authorization consent is required, {@code false} otherwise
	 */
	public boolean isConsentRequired() {
		return this.consentRequired;
	}

	/**
	 * Returns {@code true} if this {@code Authentication} represents an authorization consent request,
	 * {@code false} otherwise.
	 *
	 * @return {@code true} if this {@code Authentication} represents an authorization consent request, {@code false} otherwise
	 */
	public boolean isConsent() {
		return this.consent;
	}

	/**
	 * Returns the {@link OAuth2AuthorizationCode}.
	 *
	 * @return the {@link OAuth2AuthorizationCode}
	 */
	@Nullable
	public OAuth2AuthorizationCode getAuthorizationCode() {
		return this.authorizationCode;
	}

	/**
	 * Returns a new {@link Builder}, initialized with the given client identifier
	 * and {@code Principal} (Resource Owner).
	 *
	 * @param clientId the client identifier
	 * @param principal the {@code Principal} (Resource Owner)
	 * @return the {@link Builder}
	 */
	public static Builder with(@NonNull String clientId, @NonNull Authentication principal) {
		Assert.hasText(clientId, "clientId cannot be empty");
		Assert.notNull(principal, "principal cannot be null");
		return new Builder(clientId, principal);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
	 */
	public static final class Builder implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		private String authorizationUri;
		private String clientId;
		private Authentication principal;
		private String redirectUri;
		private Set<String> scopes;
		private String state;
		private Map<String, Object> additionalParameters;
		private boolean consentRequired;
		private boolean consent;
		private OAuth2AuthorizationCode authorizationCode;

		private Builder(String clientId, Authentication principal) {
			this.clientId = clientId;
			this.principal = principal;
		}

		/**
		 * Sets the authorization URI.
		 *
		 * @param authorizationUri the authorization URI
		 * @return the {@link Builder}
		 */
		public Builder authorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
			return this;
		}

		/**
		 * Sets the redirect uri.
		 *
		 * @param redirectUri the redirect uri
		 * @return the {@link Builder}
		 */
		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		/**
		 * Sets the requested (or authorized) scope(s).
		 *
		 * @param scopes the requested (or authorized) scope(s)
		 * @return the {@link Builder}
		 */
		public Builder scopes(Set<String> scopes) {
			if (scopes != null) {
				this.scopes = new HashSet<>(scopes);
			}
			return this;
		}

		/**
		 * Sets the state.
		 *
		 * @param state the state
		 * @return the {@link Builder}
		 */
		public Builder state(String state) {
			this.state = state;
			return this;
		}

		/**
		 * Sets the additional parameters.
		 *
		 * @param additionalParameters the additional parameters
		 * @return the {@link Builder}
		 */
		public Builder additionalParameters(Map<String, Object> additionalParameters) {
			if (additionalParameters != null) {
				this.additionalParameters = new HashMap<>(additionalParameters);
			}
			return this;
		}

		/**
		 * Set to {@code true} if authorization consent is required, {@code false} otherwise.
		 *
		 * @param consentRequired {@code true} if authorization consent is required, {@code false} otherwise
		 * @return the {@link Builder}
		 */
		public Builder consentRequired(boolean consentRequired) {
			this.consentRequired = consentRequired;
			return this;
		}

		/**
		 * Set to {@code true} if this {@code Authentication} represents an authorization consent request, {@code false} otherwise.
		 *
		 * @param consent {@code true} if this {@code Authentication} represents an authorization consent request, {@code false} otherwise
		 * @return the {@link Builder}
		 */
		public Builder consent(boolean consent) {
			this.consent = consent;
			return this;
		}

		/**
		 * Sets the {@link OAuth2AuthorizationCode}.
		 *
		 * @param authorizationCode the {@link OAuth2AuthorizationCode}
		 * @return the {@link Builder}
		 */
		public Builder authorizationCode(OAuth2AuthorizationCode authorizationCode) {
			this.authorizationCode = authorizationCode;
			return this;
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
		 *
		 * @return the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
		 */
		public OAuth2AuthorizationCodeRequestAuthenticationToken build() {
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			if (this.consent) {
				Assert.hasText(this.state, "state cannot be empty");
			}

			OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
					new OAuth2AuthorizationCodeRequestAuthenticationToken();

			authentication.authorizationUri = this.authorizationUri;
			authentication.clientId = this.clientId;
			authentication.principal = this.principal;
			authentication.redirectUri = this.redirectUri;
			authentication.scopes = Collections.unmodifiableSet(
					!CollectionUtils.isEmpty(this.scopes) ?
							this.scopes :
							Collections.emptySet());
			authentication.state = this.state;
			authentication.additionalParameters = Collections.unmodifiableMap(
					!CollectionUtils.isEmpty(this.additionalParameters) ?
							this.additionalParameters :
							Collections.emptyMap());
			authentication.consentRequired = this.consentRequired;
			authentication.consent = this.consent;
			authentication.authorizationCode = this.authorizationCode;
			if (this.authorizationCode != null || this.consentRequired) {
				authentication.setAuthenticated(true);
			}

			return authentication;
		}

	}

}
