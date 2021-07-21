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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link ClientSettings}.
 *
 * @author Joe Grandja
 */
public class ClientSettingsTests {

	@Test
	public void constructorWhenDefaultThenDefaultsAreSet() {
		ClientSettings clientSettings = new ClientSettings();
		assertThat(clientSettings.settings()).hasSize(2);
		assertThat(clientSettings.requireProofKey()).isFalse();
		assertThat(clientSettings.requireAuthorizationConsent()).isFalse();
	}

	@Test
	public void constructorWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new ClientSettings(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("settings cannot be null");
	}

	@Test
	public void requireProofKeyWhenTrueThenSet() {
		ClientSettings clientSettings = new ClientSettings().requireProofKey(true);
		assertThat(clientSettings.requireProofKey()).isTrue();
	}

	@Test
	public void requireAuthorizationConsentWhenTrueThenSet() {
		ClientSettings clientSettings = new ClientSettings().requireAuthorizationConsent(true);
		assertThat(clientSettings.requireAuthorizationConsent()).isTrue();
	}

	@Test
	public void settingWhenCalledThenReturnClientSettings() {
		ClientSettings clientSettings = new ClientSettings()
				.<ClientSettings>setting("name1", "value1")
				.requireProofKey(true)
				.<ClientSettings>settings(settings -> settings.put("name2", "value2"))
				.requireAuthorizationConsent(true);
		assertThat(clientSettings.settings()).hasSize(4);
		assertThat(clientSettings.requireProofKey()).isTrue();
		assertThat(clientSettings.requireAuthorizationConsent()).isTrue();
		assertThat(clientSettings.<String>setting("name1")).isEqualTo("value1");
		assertThat(clientSettings.<String>setting("name2")).isEqualTo("value2");
	}
}
