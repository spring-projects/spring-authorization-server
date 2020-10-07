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
package org.springframework.security.oauth2.server.authorization.config;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * A facility for token configuration settings.
 *
 * @author Joe Grandja
 * @since 0.0.2
 * @see Settings
 */
public class TokenSettings extends Settings {
	private static final String TOKEN_SETTING_BASE = "spring.security.oauth2.authorization-server.token.";
	public static final String ACCESS_TOKEN_TIME_TO_LIVE = TOKEN_SETTING_BASE.concat("access-token-time-to-live");
	public static final String ENABLE_REFRESH_TOKENS = TOKEN_SETTING_BASE.concat("enable-refresh-tokens");
	public static final String REUSE_REFRESH_TOKENS = TOKEN_SETTING_BASE.concat("reuse-refresh-tokens");
	public static final String REFRESH_TOKEN_TIME_TO_LIVE = TOKEN_SETTING_BASE.concat("refresh-token-time-to-live");

	/**
	 * Constructs a {@code TokenSettings}.
	 */
	public TokenSettings() {
		this(defaultSettings());
	}

	/**
	 * Constructs a {@code TokenSettings} using the provided parameters.
	 *
	 * @param settings the initial settings
	 */
	public TokenSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Returns the time-to-live for an access token. The default is 5 minutes.
	 *
	 * @return the time-to-live for an access token
	 */
	public Duration accessTokenTimeToLive() {
		return setting(ACCESS_TOKEN_TIME_TO_LIVE);
	}

	/**
	 * Set the time-to-live for an access token.
	 *
	 * @param accessTokenTimeToLive the time-to-live for an access token
	 * @return the {@link TokenSettings}
	 */
	public TokenSettings accessTokenTimeToLive(Duration accessTokenTimeToLive) {
		setting(ACCESS_TOKEN_TIME_TO_LIVE, accessTokenTimeToLive);
		return this;
	}

	/**
	 * Returns {@code true} if refresh tokens support is enabled.
	 * This include generation of refresh token as a part of Authorization Code Grant flow and support of Refresh Token
	 * Grant flow. The default is {@code true}.
	 *
	 * @return {@code true} if the client support refresh token, {@code false} otherwise
	 */
	public boolean enableRefreshTokens() {
		return setting(ENABLE_REFRESH_TOKENS);
	}

	/**
	 * Set to {@code true} to enable refresh tokens support.
	 * This include generation of refresh token as a part of Authorization Code Grant flow and support of Refresh Token
	 * Grant flow.
	 *
	 * @param enableRefreshTokens {@code true} to enable refresh token grant support, {@code false} otherwise
	 * @return the {@link TokenSettings}
	 */
	public TokenSettings enableRefreshTokens(boolean enableRefreshTokens) {
		setting(ENABLE_REFRESH_TOKENS, enableRefreshTokens);
		return this;
	}

	/**
	 * Returns {@code true} if existing refresh token is re-used when a new access token is requested via Refresh Token grant,
	 * or {@code false} if a new refresh token is generated.
	 * The default is {@code false}.
	 */
	public boolean reuseRefreshTokens() {
		return setting(REUSE_REFRESH_TOKENS);
	}

	/**
	 * Set to {@code true} to re-use existing refresh token when new access token is requested via Refresh Token grant,
	 * or to {@code false} to generate a new refresh token.
	 * @param reuseRefreshTokens {@code true} to re-use existing refresh token, {@code false} to generate a new one
	 */
	public TokenSettings reuseRefreshTokens(boolean reuseRefreshTokens) {
		setting(REUSE_REFRESH_TOKENS, reuseRefreshTokens);
		return this;
	}

	/**
	 * Returns refresh token time-to-live. The default is 60 minutes. Always greater than {@code Duration.ZERO}.
	 * @return refresh token time-to-live
	 */
	public Duration refreshTokenTimeToLive() {
		return setting(REFRESH_TOKEN_TIME_TO_LIVE);
	}

	/**
	 * Sets refresh token time-to-live.
	 * @param refreshTokenTimeToLive refresh token time-to-live. Has to be greater than {@code Duration.ZERO}.
	 */
	public TokenSettings refreshTokenTimeToLive(Duration refreshTokenTimeToLive) {
		Assert.notNull(refreshTokenTimeToLive, "refreshTokenTimeToLive cannot be null");
		Assert.isTrue(refreshTokenTimeToLive.getSeconds() > 0, "refreshTokenTimeToLive has to be greater than Duration.ZERO");

		setting(REFRESH_TOKEN_TIME_TO_LIVE, refreshTokenTimeToLive);
		return this;
	}

	protected static Map<String, Object> defaultSettings() {
		Map<String, Object> settings = new HashMap<>();
		settings.put(ACCESS_TOKEN_TIME_TO_LIVE, Duration.ofMinutes(5));
		settings.put(ENABLE_REFRESH_TOKENS, true);
		settings.put(REUSE_REFRESH_TOKENS, false);
		settings.put(REFRESH_TOKEN_TIME_TO_LIVE, Duration.ofMinutes(60));
		return settings;
	}
}
