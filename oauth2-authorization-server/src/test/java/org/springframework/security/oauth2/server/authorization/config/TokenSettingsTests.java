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
		assertThat(tokenSettings.settings()).hasSize(4);
		assertThat(tokenSettings.accessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(5));
		assertThat(tokenSettings.enableRefreshTokens()).isTrue();
		assertThat(tokenSettings.reuseRefreshTokens()).isEqualTo(false);
		assertThat(tokenSettings.refreshTokenTimeToLive()).isEqualTo(Duration.ofMinutes(60));
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

	@Test
	public void enableRefreshTokenWhenFalseThenSet() {
		TokenSettings tokenSettings = new TokenSettings().enableRefreshTokens(false);
		assertThat(tokenSettings.enableRefreshTokens()).isFalse();
	}

	@Test
	public void reuseRefreshTokensWhenProvidedThenSet() {
		boolean reuseRefreshTokens = true;
		TokenSettings tokenSettings = new TokenSettings().reuseRefreshTokens(reuseRefreshTokens);
		assertThat(tokenSettings.reuseRefreshTokens()).isEqualTo(reuseRefreshTokens);
	}

	@Test
	public void refreshTokenTimeToLiveWhenProvidedThenSet() {
		Duration refresTokenTimeToLive = Duration.ofDays(10);
		TokenSettings tokenSettings = new TokenSettings().refreshTokenTimeToLive(refresTokenTimeToLive);
		assertThat(tokenSettings.refreshTokenTimeToLive()).isEqualTo(refresTokenTimeToLive);
	}

	@Test
	public void refreshTokenTimeToLiveWhenZeroOrNegativeThenThrowException() {
		assertThatThrownBy(() -> new TokenSettings().refreshTokenTimeToLive(null))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("refreshTokenTimeToLive cannot be null");

		assertThatThrownBy(() -> new TokenSettings().refreshTokenTimeToLive(Duration.ZERO))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("refreshTokenTimeToLive has to be greater than Duration.ZERO");

		assertThatThrownBy(() -> new TokenSettings().refreshTokenTimeToLive(Duration.ofSeconds(-10)))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("refreshTokenTimeToLive has to be greater than Duration.ZERO");
	}

	@Test
	public void settingWhenCalledThenReturnTokenSettings() {
		Duration accessTokenTimeToLive = Duration.ofMinutes(10);
		TokenSettings tokenSettings = new TokenSettings()
				.<TokenSettings>setting("name1", "value1")
				.accessTokenTimeToLive(accessTokenTimeToLive)
				.<TokenSettings>settings(settings -> settings.put("name2", "value2"));
		assertThat(tokenSettings.settings()).hasSize(6);
		assertThat(tokenSettings.accessTokenTimeToLive()).isEqualTo(accessTokenTimeToLive);
		assertThat(tokenSettings.enableRefreshTokens()).isTrue();
		assertThat(tokenSettings.reuseRefreshTokens()).isFalse();
		assertThat(tokenSettings.refreshTokenTimeToLive()).isEqualTo(Duration.ofMinutes(60));
		assertThat(tokenSettings.<String>setting("name1")).isEqualTo("value1");
		assertThat(tokenSettings.<String>setting("name2")).isEqualTo("value2");
	}
}
