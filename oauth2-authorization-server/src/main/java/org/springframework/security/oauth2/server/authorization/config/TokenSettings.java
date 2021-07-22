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
package org.springframework.security.oauth2.server.authorization.config;

import java.time.Duration;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

/**
 * A facility for token configuration settings.
 *
 * @author Joe Grandja
 * @since 0.0.2
 * @see AbstractSettings
 */
public final class TokenSettings extends AbstractSettings {
	private static final String TOKEN_SETTING_BASE = "setting.token.";
	public static final String ACCESS_TOKEN_TIME_TO_LIVE = TOKEN_SETTING_BASE.concat("access-token-time-to-live");
	public static final String REUSE_REFRESH_TOKENS = TOKEN_SETTING_BASE.concat("reuse-refresh-tokens");
	public static final String REFRESH_TOKEN_TIME_TO_LIVE = TOKEN_SETTING_BASE.concat("refresh-token-time-to-live");
	public static final String ID_TOKEN_SIGNATURE_ALGORITHM = TOKEN_SETTING_BASE.concat("id-token-signature-algorithm");

	private TokenSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Returns the time-to-live for an access token. The default is 5 minutes.
	 *
	 * @return the time-to-live for an access token
	 */
	public Duration getAccessTokenTimeToLive() {
		return getSetting(ACCESS_TOKEN_TIME_TO_LIVE);
	}

	/**
	 * Returns {@code true} if refresh tokens are reused when returning the access token response,
	 * or {@code false} if a new refresh token is issued. The default is {@code true}.
	 */
	public boolean isReuseRefreshTokens() {
		return getSetting(REUSE_REFRESH_TOKENS);
	}

	/**
	 * Returns the time-to-live for a refresh token. The default is 60 minutes.
	 *
	 * @return the time-to-live for a refresh token
	 */
	public Duration getRefreshTokenTimeToLive() {
		return getSetting(REFRESH_TOKEN_TIME_TO_LIVE);
	}

	/**
	 * Returns the {@link SignatureAlgorithm JWS} algorithm for signing the {@link OidcIdToken ID Token}.
	 * The default is {@link SignatureAlgorithm#RS256 RS256}.
	 *
	 * @return the {@link SignatureAlgorithm JWS} algorithm for signing the {@link OidcIdToken ID Token}
	 */
	public SignatureAlgorithm getIdTokenSignatureAlgorithm() {
		return getSetting(ID_TOKEN_SIGNATURE_ALGORITHM);
	}

	/**
	 * Constructs a new {@link Builder} with the default settings.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder()
				.accessTokenTimeToLive(Duration.ofMinutes(5))
				.reuseRefreshTokens(true)
				.refreshTokenTimeToLive(Duration.ofMinutes(60))
				.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256);
	}

	/**
	 * Constructs a new {@link Builder} with the provided settings.
	 *
	 * @param settings the settings to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withSettings(Map<String, Object> settings) {
		Assert.notEmpty(settings, "settings cannot be empty");
		return new Builder()
				.settings(s -> s.putAll(settings));
	}

	/**
	 * A builder for {@link TokenSettings}.
	 */
	public static class Builder extends AbstractBuilder<TokenSettings, Builder> {

		private Builder() {
		}

		/**
		 * Set the time-to-live for an access token. Must be greater than {@code Duration.ZERO}.
		 *
		 * @param accessTokenTimeToLive the time-to-live for an access token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder accessTokenTimeToLive(Duration accessTokenTimeToLive) {
			Assert.notNull(accessTokenTimeToLive, "accessTokenTimeToLive cannot be null");
			Assert.isTrue(accessTokenTimeToLive.getSeconds() > 0, "accessTokenTimeToLive must be greater than Duration.ZERO");
			return setting(ACCESS_TOKEN_TIME_TO_LIVE, accessTokenTimeToLive);
		}

		/**
		 * Set to {@code true} if refresh tokens are reused when returning the access token response,
		 * or {@code false} if a new refresh token is issued.
		 *
		 * @param reuseRefreshTokens {@code true} to reuse refresh tokens, {@code false} to issue new refresh tokens
		 * @return the {@link Builder} for further configuration
		 */
		public Builder reuseRefreshTokens(boolean reuseRefreshTokens) {
			return setting(REUSE_REFRESH_TOKENS, reuseRefreshTokens);
		}

		/**
		 * Set the time-to-live for a refresh token. Must be greater than {@code Duration.ZERO}.
		 *
		 * @param refreshTokenTimeToLive the time-to-live for a refresh token
		 * @return the {@link Builder} for further configuration
		 */
		public Builder refreshTokenTimeToLive(Duration refreshTokenTimeToLive) {
			Assert.notNull(refreshTokenTimeToLive, "refreshTokenTimeToLive cannot be null");
			Assert.isTrue(refreshTokenTimeToLive.getSeconds() > 0, "refreshTokenTimeToLive must be greater than Duration.ZERO");
			return setting(REFRESH_TOKEN_TIME_TO_LIVE, refreshTokenTimeToLive);
		}

		/**
		 * Sets the {@link SignatureAlgorithm JWS} algorithm for signing the {@link OidcIdToken ID Token}.
		 *
		 * @param idTokenSignatureAlgorithm the {@link SignatureAlgorithm JWS} algorithm for signing the {@link OidcIdToken ID Token}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder idTokenSignatureAlgorithm(SignatureAlgorithm idTokenSignatureAlgorithm) {
			Assert.notNull(idTokenSignatureAlgorithm, "idTokenSignatureAlgorithm cannot be null");
			return setting(ID_TOKEN_SIGNATURE_ALGORITHM, idTokenSignatureAlgorithm);
		}

		/**
		 * Builds the {@link TokenSettings}.
		 *
		 * @return the {@link TokenSettings}
		 */
		@Override
		public TokenSettings build() {
			return new TokenSettings(getSettings());
		}

	}

}
