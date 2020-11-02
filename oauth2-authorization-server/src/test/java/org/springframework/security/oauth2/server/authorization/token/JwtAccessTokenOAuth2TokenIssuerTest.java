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

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.shaded.json.JSONArray;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.crypto.key.AsymmetricKey;
import org.springframework.security.crypto.key.StaticKeyGeneratingCryptoKeySource;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jose.jws.NimbusJwsEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

/**
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class JwtAccessTokenOAuth2TokenIssuerTest {

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
	private final String testResourceOwnerName = "test-user";
	private final Instant now = Instant.now();

	private JwtDecoder jwtDecoder;
	private JwtEncoder jwtEncoder;
	private JwtAccessTokenOAuth2TokenIssuer tokenIssuer;

	@Before
	public void setUp() {
		StaticKeyGeneratingCryptoKeySource keySource = new StaticKeyGeneratingCryptoKeySource();
		AsymmetricKey key = (AsymmetricKey) keySource.getKeys().stream()
				.filter(cryptoKey -> "RSA".equals(cryptoKey.getAlgorithm()))
				.findFirst().orElseThrow(() -> new AssertionError("Public Key not found"));

		RSAPublicKey publicKey = (RSAPublicKey) key.getPublicKey();

		this.jwtEncoder = new NimbusJwsEncoder(keySource);
		this.jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
		this.tokenIssuer = new JwtAccessTokenOAuth2TokenIssuer(jwtEncoder);
		this.tokenIssuer.setClock(Clock.fixed(this.now, ZoneId.of("UTC")));
	}

	@Test
	public void issueWhenValidRequestThenSetTokenLifetime() {
		OAuth2AuthorizationGrantContext tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext().build();

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest).getToken();
		assertThat(accessToken.getIssuedAt()).isEqualTo(this.now);
		assertThat(accessToken.getExpiresAt()).isEqualTo(this.now.plus(this.registeredClient.getTokenSettings().accessTokenTimeToLive()));
	}

	@Test
	public void issueWhenValidRequestThenSetClaims() {
		Set<String> expectedScopes = Collections.singleton("test-scope");
		OAuth2AuthorizationGrantContext tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.claim("scope", expectedScopes)
				.claim("another-claim", "claim-value")
				.build();

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest).getToken();
		Jwt decodedJwt = decode(accessToken.getTokenValue());

		JSONArray actualScopes = decodedJwt.getClaim("scope");
		assertThat(actualScopes).containsAll(expectedScopes);
		assertThat(decodedJwt.getClaimAsString("another-claim")).isEqualTo("claim-value");
	}

	@Test
	public void issueWhenValidRequestThenSetAccessTokenScopes() {
		Set<String> expectedScopes = Collections.singleton("test-scope");
		OAuth2AuthorizationGrantContext tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.claim("scope", expectedScopes)
				.build();

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest).getToken();
		assertThat(accessToken.getScopes()).containsAll(expectedScopes);
	}

	@Test
	public void issueWhenValidRequestThenSetOAuth2Claims() {
		OAuth2AuthorizationGrantContext tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext().build();

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest).getToken();
		Jwt decodedJwt = decode(accessToken.getTokenValue());

		assertThat(decodedJwt.getClaims())
				.containsEntry("sub", this.testResourceOwnerName)
				.containsEntry("aud", Collections.singletonList(this.registeredClient.getClientId()))
				.containsEntry("iat", this.now.truncatedTo(ChronoUnit.SECONDS))
				.containsEntry("nbf", this.now.truncatedTo(ChronoUnit.SECONDS));
	}

	@Test
	public void issueWhenCustomizerProvidedThenTokenCustomized() {
		OAuth2AuthorizationGrantContext tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext().build();
		this.tokenIssuer.setCustomizer(builder -> {
			builder.claims(claims -> claims.put("new-claim", "claim-value"));
			builder.headers(headers -> headers.put("new-header", "header-value"));
		});

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest).getToken();
		Jwt decodedJwt = decode(accessToken.getTokenValue());

		assertThat(decodedJwt.getClaims()).containsEntry("new-claim", "claim-value");
		assertThat(decodedJwt.getHeaders()).containsEntry("new-header", "header-value");
	}

	@Test
	public void issueWhenValidRequestThenReturnTokenMetadata() {
		Set<String> testScopes = Collections.singleton("test-scope");
		OAuth2AuthorizationGrantContext tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.claim("scope", testScopes)
				.build();

		OAuth2TokenMetadata tokenMetadata = this.tokenIssuer.issue(tokenRequest).getMetadata();
		Jwt jwt = tokenMetadata.getMetadata(OAuth2TokenMetadata.TOKEN);
		assertThat(jwt.getClaims())
				.containsEntry("sub", this.testResourceOwnerName)
				.containsEntry("aud", Collections.singletonList(this.registeredClient.getClientId()))
				.containsEntry("iat", this.now)
				.containsEntry("exp", this.now.plus(tokenRequest.getRegisteredClient().getTokenSettings().accessTokenTimeToLive()))
				.containsEntry("nbf", this.now);
	}

	private Jwt decode(String tokenValue) {
		return this.jwtDecoder.decode(tokenValue);
	}
}
