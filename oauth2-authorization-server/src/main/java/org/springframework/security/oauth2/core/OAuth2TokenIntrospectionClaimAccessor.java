/*
 * Copyright 2002-2020 the original author or authors.
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

import java.net.URL;
import java.time.Instant;
import java.util.List;

/*
 * TODO
 * This class is "mostly" a copy from Spring Security and should be removed after upgrading to Spring Security 5.6.0 GA.
 * The major changes made between the Spring Security class and this one are:
 *	1) Class renamed from `OAuth2IntrospectionClaimAccessor` to `OAuth2TokenIntrospectionClaimAccessor`
 *	2) Moved from package `org.springframework.security.oauth2.server.resource.introspection` to `org.springframework.security.oauth2.core`
 *
 * gh-9647 Move and rename OAuth2IntrospectionClaimAccessor/Names
 * https://github.com/spring-projects/spring-security/issues/9647
 */

/**
 * A {@link ClaimAccessor} for the &quot;claims&quot; that may be contained in the
 * Introspection Response.
 *
 * @author David Kovac
 * @since 5.4
 * @see ClaimAccessor
 * @see OAuth2TokenIntrospectionClaimNames
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc7662#section-2.2">Introspection Response</a>
 */
public interface OAuth2TokenIntrospectionClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the indicator {@code (active)} whether or not the token is currently active
	 * @return the indicator whether or not the token is currently active
	 */
	default boolean isActive() {
		return Boolean.TRUE.equals(getClaimAsBoolean(OAuth2TokenIntrospectionClaimNames.ACTIVE));
	}

	/**
	 * Returns the scopes {@code (scope)} associated with the token
	 * @return the scopes associated with the token
	 */
	default List<String> getScopes() {
		return getClaimAsStringList(OAuth2TokenIntrospectionClaimNames.SCOPE);
	}

	/**
	 * Returns the client identifier {@code (client_id)} for the token
	 * @return the client identifier for the token
	 */
	default String getClientId() {
		return getClaimAsString(OAuth2TokenIntrospectionClaimNames.CLIENT_ID);
	}

	/**
	 * Returns a human-readable identifier {@code (username)} for the resource owner that
	 * authorized the token
	 * @return a human-readable identifier for the resource owner that authorized the
	 * token
	 */
	default String getUsername() {
		return getClaimAsString(OAuth2TokenIntrospectionClaimNames.USERNAME);
	}

	/**
	 * Returns the type of the token {@code (token_type)}, for example {@code bearer}.
	 * @return the type of the token, for example {@code bearer}.
	 */
	default String getTokenType() {
		return getClaimAsString(OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE);
	}

	/**
	 * Returns a timestamp {@code (exp)} indicating when the token expires
	 * @return a timestamp indicating when the token expires
	 */
	default Instant getExpiresAt() {
		return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.EXP);
	}

	/**
	 * Returns a timestamp {@code (iat)} indicating when the token was issued
	 * @return a timestamp indicating when the token was issued
	 */
	default Instant getIssuedAt() {
		return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.IAT);
	}

	/**
	 * Returns a timestamp {@code (nbf)} indicating when the token is not to be used
	 * before
	 * @return a timestamp indicating when the token is not to be used before
	 */
	default Instant getNotBefore() {
		return getClaimAsInstant(OAuth2TokenIntrospectionClaimNames.NBF);
	}

	/**
	 * Returns usually a machine-readable identifier {@code (sub)} of the resource owner
	 * who authorized the token
	 * @return usually a machine-readable identifier of the resource owner who authorized
	 * the token
	 */
	default String getSubject() {
		return getClaimAsString(OAuth2TokenIntrospectionClaimNames.SUB);
	}

	/**
	 * Returns the intended audience {@code (aud)} for the token
	 * @return the intended audience for the token
	 */
	default List<String> getAudience() {
		return getClaimAsStringList(OAuth2TokenIntrospectionClaimNames.AUD);
	}

	/**
	 * Returns the issuer {@code (iss)} of the token
	 * @return the issuer of the token
	 */
	default URL getIssuer() {
		return getClaimAsURL(OAuth2TokenIntrospectionClaimNames.ISS);
	}

	/**
	 * Returns the identifier {@code (jti)} for the token
	 * @return the identifier for the token
	 */
	default String getId() {
		return getClaimAsString(OAuth2TokenIntrospectionClaimNames.JTI);
	}

}
