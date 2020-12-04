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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

/**
 * @author Alexey Nesterov
 * @since 0.0.3
 */
class OAuth2TokenIssuerUtil {

	private static final StringKeyGenerator TOKEN_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

	static Jwt issueJwtAccessToken(JwtEncoder jwtEncoder, String subject, String audience, Set<String> scopes, Duration tokenTimeToLive) {
		JoseHeader joseHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();

		String issuer = "http://auth-server:9000";		// TODO Allow configuration for issuer claim
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(tokenTimeToLive);

		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
											.issuer(issuer)
											.subject(subject)
											.audience(Collections.singletonList(audience))
											.issuedAt(issuedAt)
											.expiresAt(expiresAt)
											.notBefore(issuedAt)
											.claim(OAuth2ParameterNames.SCOPE, scopes)
											.build();

		return jwtEncoder.encode(joseHeader, jwtClaimsSet);
	}

	static Jwt issueIdToken(JwtEncoder jwtEncoder, String subject, String audience, String nonce) {
		JoseHeader joseHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();

		String issuer = "http://auth-server:9000";		// TODO Allow configuration for issuer claim
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);		// TODO Allow configuration for id token time-to-live

		JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
				.issuer(issuer)
				.subject(subject)
				.audience(Collections.singletonList(audience))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.claim(IdTokenClaimNames.AZP, audience);
		if (StringUtils.hasText(nonce)) {
			builder.claim(IdTokenClaimNames.NONCE, nonce);
		}

		// TODO Add 'auth_time' claim

		JwtClaimsSet jwtClaimsSet = builder.build();

		return jwtEncoder.encode(joseHeader, jwtClaimsSet);
	}

	static OAuth2RefreshToken issueRefreshToken(Duration tokenTimeToLive) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(tokenTimeToLive);

		return new OAuth2RefreshToken2(TOKEN_GENERATOR.generateKey(), issuedAt, expiresAt);
	}
}
