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

import java.util.HashMap;
import java.util.Map;

/**
 * A facility for client configuration settings.
 *
 * @author Joe Grandja
 * @since 0.0.2
 * @see Settings
 */
public class ClientSettings extends Settings {
	private static final String CLIENT_SETTING_BASE = "setting.client.";
	public static final String REQUIRE_PROOF_KEY = CLIENT_SETTING_BASE.concat("require-proof-key");
	public static final String REQUIRE_USER_CONSENT = CLIENT_SETTING_BASE.concat("require-user-consent");

	/**
	 * Constructs a {@code ClientSettings}.
	 */
	public ClientSettings() {
		this(defaultSettings());
	}

	/**
	 * Constructs a {@code ClientSettings} using the provided parameters.
	 *
	 * @param settings the initial settings
	 */
	public ClientSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Returns {@code true} if the client is required to provide a proof key challenge and verifier
	 * when performing the Authorization Code Grant flow. The default is {@code false}.
	 *
	 * @return {@code true} if the client is required to provide a proof key challenge and verifier, {@code false} otherwise
	 */
	public boolean requireProofKey() {
		return setting(REQUIRE_PROOF_KEY);
	}

	/**
	 * Set to {@code true} if the client is required to provide a proof key challenge and verifier
	 * when performing the Authorization Code Grant flow.
	 *
	 * @param requireProofKey {@code true} if the client is required to provide a proof key challenge and verifier, {@code false} otherwise
	 * @return the {@link ClientSettings}
	 */
	public ClientSettings requireProofKey(boolean requireProofKey) {
		setting(REQUIRE_PROOF_KEY, requireProofKey);
		return this;
	}

	/**
	 * Returns {@code true} if the user's consent is required when the client requests access.
	 * The default is {@code false}.
	 *
	 * @return {@code true} if the user's consent is required when the client requests access, {@code false} otherwise
	 */
	public boolean requireUserConsent() {
		return setting(REQUIRE_USER_CONSENT);
	}

	/**
	 * Set to {@code true} if the user's consent is required when the client requests access.
	 * This applies to all interactive flows (e.g. {@code authorization_code} and {@code device_code}).
	 *
	 * @param requireUserConsent {@code true} if the user's consent is required when the client requests access, {@code false} otherwise
	 * @return the {@link ClientSettings}
	 */
	public ClientSettings requireUserConsent(boolean requireUserConsent) {
		setting(REQUIRE_USER_CONSENT, requireUserConsent);
		return this;
	}

	protected static Map<String, Object> defaultSettings() {
		Map<String, Object> settings = new HashMap<>();
		settings.put(REQUIRE_PROOF_KEY, false);
		settings.put(REQUIRE_USER_CONSENT, false);
		return settings;
	}
}
