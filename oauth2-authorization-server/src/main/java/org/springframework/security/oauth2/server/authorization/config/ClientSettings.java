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

import java.util.Map;

import org.springframework.util.Assert;

/**
 * A facility for client configuration settings.
 *
 * @author Joe Grandja
 * @since 0.0.2
 * @see AbstractSettings
 */
public final class ClientSettings extends AbstractSettings {
	private static final String CLIENT_SETTING_BASE = "setting.client.";
	public static final String REQUIRE_PROOF_KEY = CLIENT_SETTING_BASE.concat("require-proof-key");
	public static final String REQUIRE_AUTHORIZATION_CONSENT = CLIENT_SETTING_BASE.concat("require-authorization-consent");

	private ClientSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Returns {@code true} if the client is required to provide a proof key challenge and verifier
	 * when performing the Authorization Code Grant flow. The default is {@code false}.
	 *
	 * @return {@code true} if the client is required to provide a proof key challenge and verifier, {@code false} otherwise
	 */
	public boolean isRequireProofKey() {
		return getSetting(REQUIRE_PROOF_KEY);
	}

	/**
	 * Returns {@code true} if authorization consent is required when the client requests access.
	 * The default is {@code false}.
	 *
	 * @return {@code true} if authorization consent is required when the client requests access, {@code false} otherwise
	 */
	public boolean isRequireAuthorizationConsent() {
		return getSetting(REQUIRE_AUTHORIZATION_CONSENT);
	}

	/**
	 * Constructs a new {@link Builder} with the default settings.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder()
				.requireProofKey(false)
				.requireAuthorizationConsent(false);
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
	 * A builder for {@link ClientSettings}.
	 */
	public static class Builder extends AbstractBuilder<ClientSettings, Builder> {

		private Builder() {
		}

		/**
		 * Set to {@code true} if the client is required to provide a proof key challenge and verifier
		 * when performing the Authorization Code Grant flow.
		 *
		 * @param requireProofKey {@code true} if the client is required to provide a proof key challenge and verifier, {@code false} otherwise
		 * @return the {@link Builder} for further configuration
		 */
		public Builder requireProofKey(boolean requireProofKey) {
			return setting(REQUIRE_PROOF_KEY, requireProofKey);
		}

		/**
		 * Set to {@code true} if authorization consent is required when the client requests access.
		 * This applies to all interactive flows (e.g. {@code authorization_code} and {@code device_code}).
		 *
		 * @param requireAuthorizationConsent {@code true} if authorization consent is required when the client requests access, {@code false} otherwise
		 * @return the {@link Builder} for further configuration
		 */
		public Builder requireAuthorizationConsent(boolean requireAuthorizationConsent) {
			return setting(REQUIRE_AUTHORIZATION_CONSENT, requireAuthorizationConsent);
		}

		/**
		 * Builds the {@link ClientSettings}.
		 *
		 * @return the {@link ClientSettings}
		 */
		@Override
		public ClientSettings build() {
			return new ClientSettings(getSettings());
		}

	}

}
