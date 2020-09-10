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

	protected static Map<String, Object> defaultSettings() {
		Map<String, Object> settings = new HashMap<>();
		settings.put(ACCESS_TOKEN_TIME_TO_LIVE, Duration.ofMinutes(5));
		return settings;
	}
}
