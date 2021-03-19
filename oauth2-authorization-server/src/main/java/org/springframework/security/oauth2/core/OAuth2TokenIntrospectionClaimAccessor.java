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

import java.net.URL;
import java.time.Instant;
import java.util.List;

/**
 * TODO This class is a copy from Spring Security (Resource Server) with the difference that we rely on the existing
 * {@code OAuth2ParameterNames} and {@code JwtClaimNames} claims. It should be consolidated when merging this codebase into Spring
 * Security.
 *
 * A {@link ClaimAccessor} for the &quot;claims&quot; that may be contained in the Introspection Response.
 *
 * @author David Kovac
 * @author Gerardo Roza
 * @since 0.1.1
 * @see ClaimAccessor
 * @see OAuth2IntrospectionClaimNames
 * @see OAuth2IntrospectionAuthenticatedPrincipal
 * @see <a target="_blank" href= "https://tools.ietf.org/html/rfc7662#section-2.2">Introspection Response</a>
 */
public interface OAuth2TokenIntrospectionClaimAccessor extends ClaimAccessor {

	String ACTIVE = "active";

	/**
	 * Returns the indicator {@code (active)} whether or not the token is currently active
	 *
	 * @return the indicator whether or not the token is currently active
	 */
	default boolean isActive() {
		return Boolean.TRUE.equals(this.getClaimAsBoolean(ACTIVE));
	}

	/**
	 * Returns the scopes {@code (scope)} associated with the token
	 *
	 * @return the scopes associated with the token
	 */
	default String getScope() {
		return this.getClaimAsString(SCOPE);
	}

	/**
	 * Returns the client identifier {@code (client_id)} for the token
	 *
	 * @return the client identifier for the token
	 */
	default String getClientId() {
		return this.getClaimAsString(CLIENT_ID);
	}

	/**
	 * Returns a human-readable identifier {@code (username)} for the resource owner that authorized the token
	 *
	 * @return a human-readable identifier for the resource owner that authorized the token
	 */
	default String getUsername() {
		return this.getClaimAsString(USERNAME);
	}

	/**
	 * Returns the type of the token {@code (token_type)}, for example {@code bearer}.
	 *
	 * @return the type of the token, for example {@code bearer}.
	 */
	default String getTokenType() {
		return this.getClaimAsString(TOKEN_TYPE);
	}

	/**
	 * Returns a timestamp {@code (exp)} indicating when the token expires
	 *
	 * @return a timestamp indicating when the token expires
	 */
	default Instant getExpiresAt() {
		return this.getClaimAsInstant(EXP);
	}

	/**
	 * Returns a timestamp {@code (iat)} indicating when the token was issued
	 *
	 * @return a timestamp indicating when the token was issued
	 */
	default Instant getIssuedAt() {
		return this.getClaimAsInstant(IAT);
	}

	/**
	 * Returns a timestamp {@code (nbf)} indicating when the token is not to be used before
	 *
	 * @return a timestamp indicating when the token is not to be used before
	 */
	default Instant getNotBefore() {
		return this.getClaimAsInstant(NBF);
	}

	/**
	 * Returns usually a machine-readable identifier {@code (sub)} of the resource owner who authorized the token
	 *
	 * @return usually a machine-readable identifier of the resource owner who authorized the token
	 */
	default String getSubject() {
		return this.getClaimAsString(SUB);
	}

	/**
	 * Returns the intended audience {@code (aud)} for the token
	 *
	 * @return the intended audience for the token
	 */
	default List<String> getAudience() {
		return this.getClaimAsStringList(AUD);
	}

	/**
	 * Returns the issuer {@code (iss)} of the token
	 *
	 * @return the issuer of the token
	 */
	default URL getIssuer() {
		return this.getClaimAsURL(ISS);
	}

	/**
	 * Returns the identifier {@code (jti)} for the token
	 *
	 * @return the identifier for the token
	 */
	default String getId() {
		return this.getClaimAsString(JTI);
	}

}
