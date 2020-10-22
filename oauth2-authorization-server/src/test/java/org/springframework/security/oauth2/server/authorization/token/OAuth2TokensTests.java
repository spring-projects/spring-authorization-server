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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2Tokens}.
 *
 * @author Joe Grandja
 */
public class OAuth2TokensTests {
	private OAuth2AccessToken accessToken;
	private OAuth2RefreshToken refreshToken;
	private OidcIdToken idToken;

	@Before
	public void setUp() {
		Instant issuedAt = Instant.now();
		this.accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER,
				"access-token",
				issuedAt,
				issuedAt.plus(Duration.ofMinutes(5)),
				new HashSet<>(Arrays.asList("read", "write")));
		this.refreshToken = new OAuth2RefreshToken(
				"refresh-token",
				issuedAt);
		this.idToken = OidcIdToken.withTokenValue("id-token")
				.issuer("https://provider.com")
				.subject("subject")
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plus(Duration.ofMinutes(30)))
				.build();
	}

	@Test
	public void accessTokenWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Tokens.builder().accessToken(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be null");
	}

	@Test
	public void refreshTokenWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Tokens.builder().refreshToken(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be null");
	}

	@Test
	public void tokenWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Tokens.builder().token(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be null");
	}

	@Test
	public void getTokenWhenTokenTypeNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Tokens.builder().build().getToken(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenType cannot be null");
	}

	@Test
	public void getTokenMetadataWhenTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Tokens.builder().build().getTokenMetadata(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be null");
	}

	@Test
	public void fromWhenTokensNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Tokens.from(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokens cannot be null");
	}

	@Test
	public void fromWhenTokensProvidedThenCopied() {
		OAuth2Tokens tokens = OAuth2Tokens.builder()
				.accessToken(this.accessToken)
				.refreshToken(this.refreshToken)
				.token(this.idToken)
				.build();
		OAuth2Tokens tokensResult = OAuth2Tokens.from(tokens).build();

		assertThat(tokensResult.getAccessToken()).isEqualTo(tokens.getAccessToken());
		assertThat(tokensResult.getTokenMetadata(tokensResult.getAccessToken()))
				.isEqualTo(tokens.getTokenMetadata(tokens.getAccessToken()));

		assertThat(tokensResult.getRefreshToken()).isEqualTo(tokens.getRefreshToken());
		assertThat(tokensResult.getTokenMetadata(tokensResult.getRefreshToken()))
				.isEqualTo(tokens.getTokenMetadata(tokens.getRefreshToken()));

		assertThat(tokensResult.getToken(OidcIdToken.class)).isEqualTo(tokens.getToken(OidcIdToken.class));
		assertThat(tokensResult.getTokenMetadata(tokensResult.getToken(OidcIdToken.class)))
				.isEqualTo(tokens.getTokenMetadata(tokens.getToken(OidcIdToken.class)));
	}

	@Test
	public void buildWhenTokenMetadataNotProvidedThenDefaultsAreSet() {
		OAuth2Tokens tokens = OAuth2Tokens.builder()
				.accessToken(this.accessToken)
				.refreshToken(this.refreshToken)
				.token(this.idToken)
				.build();

		assertThat(tokens.getAccessToken()).isEqualTo(this.accessToken);
		OAuth2TokenMetadata tokenMetadata = tokens.getTokenMetadata(tokens.getAccessToken());
		assertThat(tokenMetadata.isInvalidated()).isFalse();

		assertThat(tokens.getRefreshToken()).isEqualTo(this.refreshToken);
		tokenMetadata = tokens.getTokenMetadata(tokens.getRefreshToken());
		assertThat(tokenMetadata.isInvalidated()).isFalse();

		assertThat(tokens.getToken(OidcIdToken.class)).isEqualTo(this.idToken);
		tokenMetadata = tokens.getTokenMetadata(tokens.getToken(OidcIdToken.class));
		assertThat(tokenMetadata.isInvalidated()).isFalse();
	}

	@Test
	public void buildWhenTokenMetadataProvidedThenTokenMetadataIsSet() {
		OAuth2TokenMetadata expectedTokenMetadata = OAuth2TokenMetadata.builder().build();
		OAuth2Tokens tokens = OAuth2Tokens.builder()
				.accessToken(this.accessToken, expectedTokenMetadata)
				.refreshToken(this.refreshToken, expectedTokenMetadata)
				.token(this.idToken, expectedTokenMetadata)
				.build();

		assertThat(tokens.getAccessToken()).isEqualTo(this.accessToken);
		OAuth2TokenMetadata tokenMetadata = tokens.getTokenMetadata(tokens.getAccessToken());
		assertThat(tokenMetadata).isEqualTo(expectedTokenMetadata);

		assertThat(tokens.getRefreshToken()).isEqualTo(this.refreshToken);
		tokenMetadata = tokens.getTokenMetadata(tokens.getRefreshToken());
		assertThat(tokenMetadata).isEqualTo(expectedTokenMetadata);

		assertThat(tokens.getToken(OidcIdToken.class)).isEqualTo(this.idToken);
		tokenMetadata = tokens.getTokenMetadata(tokens.getToken(OidcIdToken.class));
		assertThat(tokenMetadata).isEqualTo(expectedTokenMetadata);
	}

	@Test
	public void getTokenMetadataWhenTokenNotFoundThenNull() {
		OAuth2TokenMetadata expectedTokenMetadata = OAuth2TokenMetadata.builder().build();
		OAuth2Tokens tokens = OAuth2Tokens.builder()
				.accessToken(this.accessToken, expectedTokenMetadata)
				.build();

		assertThat(tokens.getAccessToken()).isEqualTo(this.accessToken);
		OAuth2TokenMetadata tokenMetadata = tokens.getTokenMetadata(tokens.getAccessToken());
		assertThat(tokenMetadata).isEqualTo(expectedTokenMetadata);

		OAuth2AccessToken otherAccessToken = new OAuth2AccessToken(
				this.accessToken.getTokenType(),
				"other-access-token",
				this.accessToken.getIssuedAt(),
				this.accessToken.getExpiresAt(),
				this.accessToken.getScopes());
		assertThat(tokens.getTokenMetadata(otherAccessToken)).isNull();
	}

	@Test
	public void invalidateWhenAllTokensThenAllInvalidated() {
		OAuth2Tokens tokens = OAuth2Tokens.builder()
				.accessToken(this.accessToken)
				.refreshToken(this.refreshToken)
				.token(this.idToken)
				.build();
		tokens.invalidate();

		assertThat(tokens.getTokenMetadata(tokens.getAccessToken()).isInvalidated()).isTrue();
		assertThat(tokens.getTokenMetadata(tokens.getRefreshToken()).isInvalidated()).isTrue();
		assertThat(tokens.getTokenMetadata(tokens.getToken(OidcIdToken.class)).isInvalidated()).isTrue();
	}

	@Test
	public void invalidateWhenTokenProvidedThenInvalidated() {
		OAuth2Tokens tokens = OAuth2Tokens.builder()
				.accessToken(this.accessToken)
				.refreshToken(this.refreshToken)
				.token(this.idToken)
				.build();
		tokens.invalidate(this.accessToken);

		assertThat(tokens.getTokenMetadata(tokens.getAccessToken()).isInvalidated()).isTrue();
		assertThat(tokens.getTokenMetadata(tokens.getRefreshToken()).isInvalidated()).isFalse();
		assertThat(tokens.getTokenMetadata(tokens.getToken(OidcIdToken.class)).isInvalidated()).isFalse();
	}
}
