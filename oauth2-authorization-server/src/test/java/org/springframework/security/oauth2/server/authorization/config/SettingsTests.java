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

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link Settings}.
 *
 * @author Joe Grandja
 */
public class SettingsTests {

	@Test
	public void constructorWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new Settings(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("settings cannot be null");
	}

	@Test
	public void constructorWhenSettingsProvidedThenSettingsAreSet() {
		Map<String, Object> initialSettings = new HashMap<>();
		initialSettings.put("setting1", "value1");
		initialSettings.put("setting2", "value2");

		Settings settings = new Settings(initialSettings)
				.setting("setting3", "value3")
				.settings(s -> s.put("setting4", "value4"));

		assertThat(settings.settings()).contains(
				entry("setting1", "value1"),
				entry("setting2", "value2"),
				entry("setting3", "value3"),
				entry("setting4", "value4"));
	}

	@Test
	public void getSettingWhenNameNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new Settings().setting(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void setSettingWhenNameNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new Settings().setting(null, "value"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void setSettingWhenValueNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new Settings().setting("setting", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}
}
