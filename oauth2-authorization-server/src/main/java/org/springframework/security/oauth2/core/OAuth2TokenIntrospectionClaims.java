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

package org.springframework.security.oauth2.core;

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

import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * A representation of an OAuth 2.0 Introspection Token Response Claims.
 *
 * @author Gerardo Roza
 * @since 0.1.1
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.2">Section 2.2 - Introspection Response</a>
 */
public class OAuth2TokenIntrospectionClaims implements OAuth2TokenIntrospectionClaimAccessor, Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private static final Collection<String> SUPPORTED_FIELDS = Arrays
			.asList(ACTIVE, CLIENT_ID, SCOPE, TOKEN_TYPE, USERNAME, AUD, EXP, IAT, ISS, JTI, NBF, SUB);

	private final Map<String, Object> claims;

	private OAuth2TokenIntrospectionClaims(Map<String, Object> claims) {
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the populated Token Introspection Response claims.
	 *
	 * @return the claims
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Constructs a new {@link Builder} with the provided parameters.
	 *
	 * @param claims the params to initialize the builder
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		Builder builder = new Builder().claims(c -> c.putAll(claims));
		Optional.ofNullable(claims.get(IAT)).filter(Instant.class::isInstance).map(Instant.class::cast)
				.ifPresent(builder::issuedAt);
		Optional.ofNullable(claims.get(EXP)).filter(Instant.class::isInstance).map(Instant.class::cast)
				.ifPresent(builder::expirationTime);
		Optional.ofNullable(claims.get(NBF)).filter(Instant.class::isInstance).map(Instant.class::cast)
				.ifPresent(builder::notBefore);
		Optional.ofNullable(claims.get(TOKEN_TYPE)).filter(TokenType.class::isInstance).map(TokenType.class::cast)
				.ifPresent(builder::tokenType);
		return builder;
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
	 * A builder for {@link OAuth2TokenIntrospectionClaims}.
	 */
	public static final class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Helps configure a basic {@link OAuth2TokenIntrospectionClaims}.
		 *
		 * @param active boolean indicating whether the introspected token is active or not
		 */
		public Builder(boolean active) {
			claim(ACTIVE, active);
		}

		/**
		 * Populates the 'active' field.
		 *
		 * @param active boolean indicating whether the introspected token is active or not
		 * @return the {@link Builder} for further configurations
		 */
		public Builder active(boolean active) {
			claim(ACTIVE, active);
			return this;
		}

		/**
		 * Populates the 'scope' field.
		 *
		 * @param scope string containing a space-separated list of scopes associated with this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder scope(String scope) {
			claim(SCOPE, scope);
			return this;
		}

		/**
		 * Populates the 'client_id' field.
		 *
		 * @param clientId identifier for the OAuth 2.0 client that requested this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder clientId(String clientId) {
			claim(CLIENT_ID, clientId);
			return this;
		}

		/**
		 * Populates the 'username' field.
		 *
		 * @param username Human-readable identifier for the resource owner who authorized this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder username(String username) {
			claim(USERNAME, username);
			return this;
		}

		/**
		 * Populates the 'token_type' field.
		 *
		 * @param tokenType {@link TokenType} indicating the type of the token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tokenType(OAuth2AccessToken.TokenType tokenType) {
			claim(TOKEN_TYPE, tokenType.getValue());
			return this;
		}

		/**
		 * Populates the 'exp' (Expiration Time) field.
		 *
		 * @param expirationTime {@link Instant} indicating when this token will expire
		 * @return the {@link Builder} for further configurations
		 */
		public Builder expirationTime(Instant expirationTime) {
			claim(EXP, expirationTime.getEpochSecond());
			return this;
		}

		/**
		 * Populates the 'iat' (Issued At) field.
		 *
		 * @param issuedAt {@link Instant} indicating when this token was originally issued
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuedAt(Instant issuedAt) {
			claim(IAT, issuedAt.getEpochSecond());
			return this;
		}

		/**
		 * Populates the 'nbf' (Not Before) field.
		 *
		 * @param notBefore {@link Instant} indicating when this token is not to be used before
		 * @return the {@link Builder} for further configurations
		 */
		public Builder notBefore(Instant notBefore) {
			claim(NBF, notBefore.getEpochSecond());
			return this;
		}

		/**
		 * Populates the 'sub' (Subject) field.
		 *
		 * @param subject usually a machine-readable identifier of the resource owner who authorized this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			claim(SUB, subject);
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
			claim(AUD, audience);
			return this;
		}

		/**
		 * Populates the 'iss' (Issuer) field.
		 *
		 * @param issuer of this token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder issuer(String issuer) {
			claim(ISS, issuer);
			return this;
		}

		/**
		 * Populates the 'jti' (JWT ID) field.
		 *
		 * @param jwtId identifier for the token
		 * @return the {@link Builder} for further configurations
		 */
		public Builder jwtId(String jwtId) {
			claim(JTI, jwtId);
			return this;
		}

		/**
		 * Use this claim in the resulting {@link OAuth2TokenIntrospectionClaims}.
		 *
		 * @param name the claim name
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
		 * Provides access to every {@link #claim(String, Object)} declared so far with the possibility to add, replace, or remove.
		 *
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		private void validateClaims() {
			Assert.notNull(this.claims.get(ACTIVE), "active cannot be null");
		}

		/**
		 * Build the {@link OAuth2TokenIntrospectionClaims}
		 *
		 * @return The constructed {@link OAuth2TokenIntrospectionClaims}
		 */
		public OAuth2TokenIntrospectionClaims build() {
			Map<String, Object> responseClaims = this.claims.entrySet().stream()
					.filter(entry -> SUPPORTED_FIELDS.contains(entry.getKey()))
					.collect(toMap(Map.Entry::getKey, Map.Entry::getValue));
			validateClaims();
			return new OAuth2TokenIntrospectionClaims(responseClaims);
		}
	}
}
