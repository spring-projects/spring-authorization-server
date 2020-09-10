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

import org.junit.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link TokenSettings}.
 *
 * @author Joe Grandja
 */
public class TokenSettingsTests {

	@Test
	public void constructorWhenDefaultThenDefaultsAreSet() {
		TokenSettings tokenSettings = new TokenSettings();
		assertThat(tokenSettings.settings()).hasSize(1);
		assertThat(tokenSettings.accessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(5));
	}

	@Test
	public void constructorWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new TokenSettings(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("settings cannot be null");
	}

	@Test
	public void accessTokenTimeToLiveWhenProvidedThenSet() {
		Duration accessTokenTimeToLive = Duration.ofMinutes(10);
		TokenSettings tokenSettings = new TokenSettings().accessTokenTimeToLive(accessTokenTimeToLive);
		assertThat(tokenSettings.accessTokenTimeToLive()).isEqualTo(accessTokenTimeToLive);
	}
}
