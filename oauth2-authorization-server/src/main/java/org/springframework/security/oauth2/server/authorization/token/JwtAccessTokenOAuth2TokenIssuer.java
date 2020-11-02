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

package org.springframework.security.oauth2.server.authorization.token;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtEncoder;

/**
 * Implementation of {@link OAuth2TokenIssuer} to return {@link OAuth2AccessToken} with serialized {@link Jwt} value as
 * token value.
 *
 * @see OAuth2TokenIssuer
 *
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class JwtAccessTokenOAuth2TokenIssuer implements OAuth2TokenIssuer<OAuth2AccessToken> {

	private Clock clock = Clock.systemUTC();
	private OAuth2TokenCustomizer<JwtBuilder> customizer;

	private final JwtEncoder jwtEncoder;

	public JwtAccessTokenOAuth2TokenIssuer(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}

	void setClock(Clock clock) {
		this.clock = clock;
	}

	/**
	 * Set new token customizer. Customizer is applied before issuing the token and it is a best extension point to implement
	 * specific token generation logic.
	 *
	 * @param customizer new customizer
	 */
	public void setCustomizer(OAuth2TokenCustomizer<JwtBuilder> customizer) {
		this.customizer = customizer;
	}

	/**
	 * Issue a new Jwt access token. The generated token's claim names are compliant with RFC7519.
	 *
	 * @see OAuth2AccessToken
	 * @see Jwt
	 * @see <a href="https://tools.ietf.org/html/rfc7519#section-4">RFC7519 section 4</a>
	 *
	 * @param authorizationGrantContext the request
	 * @return a new OAuth2Token with metadata
	 */
	@Override
	public OAuth2TokenResult<OAuth2AccessToken> issue(@NonNull OAuth2AuthorizationGrantContext authorizationGrantContext) {
		Instant issuedAt = Instant.now(this.clock);
		Instant expiresAt = issuedAt.plus(authorizationGrantContext.getRegisteredClient().getTokenSettings().accessTokenTimeToLive());

		JwtBuilder tokenBuilder = JwtBuilder.withEncoder(this.jwtEncoder);
		tokenBuilder.claims(claims -> {
			claims.put(JwtClaimNames.SUB, authorizationGrantContext.getPrincipalName());
			claims.put(JwtClaimNames.AUD, Collections.singletonList(authorizationGrantContext.getRegisteredClient().getClientId()));
			claims.put(JwtClaimNames.IAT, issuedAt);
			claims.put(JwtClaimNames.EXP, expiresAt);
			claims.put(JwtClaimNames.NBF, issuedAt);
			claims.putAll(authorizationGrantContext.getClaims());
		});

		if (this.customizer != null) {
			this.customizer.customize(tokenBuilder);
		}

		Jwt jwt = tokenBuilder.build();
		Set<String> requestedScopes = getRequestedScopes(authorizationGrantContext);

		OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(), issuedAt, expiresAt, requestedScopes);
		OAuth2TokenMetadata metadata = OAuth2TokenMetadata
				.builder()
				.metadata(OAuth2TokenMetadata.TOKEN, jwt)
				.build();

		return OAuth2TokenResult.of(token, metadata);
	}

	private Set<String> getRequestedScopes(OAuth2AuthorizationGrantContext authorizationGrantContext) {
		Object scopeClaim = authorizationGrantContext.getClaims().get(OAuth2TokenClaimNames.SCOPE);
		if (scopeClaim instanceof Set) {
			return (Set<String>) scopeClaim;
		}

		if (scopeClaim instanceof Collection) {
			return new HashSet<>((Collection<String>) scopeClaim);
		}

		return null;
	}
}
