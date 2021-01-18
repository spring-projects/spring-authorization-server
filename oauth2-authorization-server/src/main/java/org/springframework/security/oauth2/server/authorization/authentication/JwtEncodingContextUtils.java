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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
final class JwtEncodingContextUtils {

	private JwtEncodingContextUtils() {
	}

	static JwtEncodingContext.Builder accessTokenContext(RegisteredClient registeredClient, OAuth2Authorization authorization) {
		// @formatter:off
		return accessTokenContext(registeredClient, authorization,
				authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES));
		// @formatter:on
	}

	static JwtEncodingContext.Builder accessTokenContext(RegisteredClient registeredClient, OAuth2Authorization authorization,
			Set<String> authorizedScopes) {
		// @formatter:off
		return accessTokenContext(registeredClient, authorization.getPrincipalName(), authorizedScopes)
				.authorization(authorization);
		// @formatter:on
	}

	static JwtEncodingContext.Builder accessTokenContext(RegisteredClient registeredClient,
			String principalName, Set<String> authorizedScopes) {

		JoseHeader.Builder headersBuilder = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256);

		String issuer = "http://auth-server:9000";        // TODO Allow configuration for issuer claim
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().accessTokenTimeToLive());

		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
				.issuer(issuer)
				.subject(principalName)
				.audience(Collections.singletonList(registeredClient.getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.notBefore(issuedAt);
		if (!CollectionUtils.isEmpty(authorizedScopes)) {
			claimsBuilder.claim(OAuth2ParameterNames.SCOPE, authorizedScopes);
		}
		// @formatter:on

		// @formatter:off
		return JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.tokenType(TokenType.ACCESS_TOKEN);
		// @formatter:on
	}

	static JwtEncodingContext.Builder idTokenContext(RegisteredClient registeredClient, OAuth2Authorization authorization) {
		JoseHeader.Builder headersBuilder = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256);

		String issuer = "http://auth-server:9000";        // TODO Allow configuration for issuer claim
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);		// TODO Allow configuration for id token time-to-live
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);
		String nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);

		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
				.issuer(issuer)
				.subject(authorization.getPrincipalName())
				.audience(Collections.singletonList(registeredClient.getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.claim(IdTokenClaimNames.AZP, registeredClient.getClientId());
		if (StringUtils.hasText(nonce)) {
			claimsBuilder.claim(IdTokenClaimNames.NONCE, nonce);
		}
		// TODO Add 'auth_time' claim
		// @formatter:on

		// @formatter:off
		return JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.authorization(authorization)
				.tokenType(new TokenType(OidcParameterNames.ID_TOKEN));
		// @formatter:on
	}

}
