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

import static java.util.Collections.emptyMap;
import static java.util.stream.Collectors.toMap;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.USERNAME;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.JTI;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.NBF;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A representation of an OAuth 2.0 Introspection Token Response.
 *
 * @author Gerardo Roza
 * @since 0.1.1
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.2">Section 2.2 - Introspection Response</a>
 */
public class OAuth2TokenIntrospectionResponse {

	public static final String ACTIVE = "active";
	private static final Collection<String> SUPPORTED_FIELDS = Arrays
			.asList(ACTIVE, CLIENT_ID, SCOPE, TOKEN_TYPE, USERNAME, AUD, EXP, IAT, ISS, JTI, NBF, SUB);

	private final Map<String, Object> parameters;

	private OAuth2TokenIntrospectionResponse(Map<String, Object> params) {
		this.parameters = params;
	}

	/**
	 * Returns the populated parameters.
	 *
	 * @return the parameters
	 */
	public Map<String, Object> getParameters() {
		return this.parameters;
	}

	/**
	 * Constructs a new {@link Builder} with the provided parameters.
	 *
	 * @param parameters the params to initialize the builder
	 */
	public static Builder withClaims(@Nullable Map<String, Object> parameters) {
		Map<String, Object> params = parameters != null ? parameters : emptyMap();
		return new Builder(params);
	}

	/**
	 * Constructs a new {@link Builder} with the required active field.
	 *
	 * @param active boolean indicating whether the introspected token is active or not to initialize the builder
	 */
	public static Builder builder(boolean active) {
		return new Builder(active);
	}

	/**
	 * A builder for {@link OAuth2TokenIntrospectionResponse}.
	 */
	public static final class Builder {

		private final Map<String, Object> params = new HashMap<>();

		private Builder(Map<String, Object> params) {
			this.params.putAll(params);
		}

		/**
		 * Helps configure a basic {@link OAuth2TokenIntrospectionResponse}.
		 *
		 * @param active boolean indicating whether the introspected token is active or not
		 */
		public Builder(boolean active) {
			this.params.put(ACTIVE, active);
		}

		/**
		 * Adds a param field. If null is passed as value, then it removes the entry.
		 *
		 * @param key
		 * @param value
		 */
		public void addParam(String key, @Nullable Object value) {
			if (value != null) {
				this.params.put(key, value);
			} else {
				this.params.remove(key);
			}
		}

		/**
		 * Populates the 'active' field.
		 *
		 * @param active boolean indicating whether the introspected token is active or not
		 * @return the {@link Builder} for further configurations
		 */
		public Builder active(boolean active) {
			this.addParam(ACTIVE, active);
			return this;
		}

		/**
		 * Populates the 'scope' field.
		 *
		 * @param scope string containing a space-separated list of scopes associated with this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder scope(String scope) {
			this.addParam(SCOPE, scope);
			return this;
		}

		/**
		 * Populates the 'client_id' field.
		 *
		 * @param clientId identifier for the OAuth 2.0 client that requested this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder clientId(String clientId) {
			this.addParam(CLIENT_ID, clientId);
			return this;
		}

		/**
		 * Populates the 'username' field.
		 *
		 * @param username Human-readable identifier for the resource owner who authorized this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder username(String username) {
			this.addParam(USERNAME, username);
			return this;
		}

		/**
		 * Populates the 'token_type' field.
		 *
		 * @param tokenType {@link TokenType} indicating the type of the token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tokenType(OAuth2AccessToken.TokenType tokenType) {
			this.addParam(TOKEN_TYPE, tokenType.getValue());
			return this;
		}

		/**
		 * Populates the 'exp' (Expiration Time) field.
		 *
		 * @param expirationTime {@link Instant} indicating when this token will expire
		 * @return the {@link Builder} for further configurations
		 */
		public Builder expirationTime(Instant expirationTime) {
			this.addParam(EXP, expirationTime.getEpochSecond());
			return this;
		}

		/**
		 * Populates the 'iat' (Issued At) field.
		 *
		 * @param issuedAt {@link Instant} indicating when this token was originally issued
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuedAt(Instant issuedAt) {
			this.addParam(IAT, issuedAt.getEpochSecond());
			return this;
		}

		/**
		 * Populates the 'nbf' (Not Before) field.
		 *
		 * @param notBefore {@link Instant} indicating when this token is not to be used before
		 * @return the {@link Builder} for further configurations
		 */
		public Builder notBefore(Instant notBefore) {
			this.addParam(NBF, notBefore.getEpochSecond());
			return this;
		}

		/**
		 * Populates the 'sub' (Subject) field.
		 *
		 * @param subject usually a machine-readable identifier of the resource owner who authorized this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			this.addParam(SUB, subject);
			return this;
		}

		/**
		 * Populates the 'aud' (Audience) field.
		 *
		 * @param audience service-specific string identifier or list of string identifiers representing the intended audience for this
		 * token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder audience(List<String> audience) {
			this.addParam(AUD, audience);
			return this;
		}

		/**
		 * Populates the 'iss' (Issuer) field.
		 *
		 * @param issuer of this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuer(String issuer) {
			this.addParam(ISS, issuer);
			return this;
		}

		/**
		 * Populates the 'jti' (JWT ID) field.
		 *
		 * @param jwtId identifier for the token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder jwtId(String jwtId) {
			this.addParam(JTI, jwtId);
			return this;
		}

		/**
		 * Build the {@link OAuth2TokenIntrospectionResponse}
		 *
		 * @return The constructed {@link OAuth2TokenIntrospectionResponse}
		 */
		public OAuth2TokenIntrospectionResponse build() {
			Map<String, Object> responseParams = this.params.entrySet().stream()
					.filter(entry -> SUPPORTED_FIELDS.contains(entry.getKey()))
					.collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
			return new OAuth2TokenIntrospectionResponse(responseParams);
		}
	}
}
