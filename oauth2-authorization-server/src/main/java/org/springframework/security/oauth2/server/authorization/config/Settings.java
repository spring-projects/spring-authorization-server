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

import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A facility for configuration settings.
 *
 * @author Joe Grandja
 * @since 0.0.2
 */
public class Settings implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final Map<String, Object> settings;

	/**
	 * Constructs a {@code Settings}.
	 */
	public Settings() {
		this.settings = new HashMap<>();
	}

	/**
	 * Constructs a {@code Settings} using the provided parameters.
	 *
	 * @param settings the initial settings
	 */
	public Settings(Map<String, Object> settings) {
		Assert.notNull(settings, "settings cannot be null");
		this.settings = new HashMap<>(settings);
	}

	/**
	 * Returns a configuration setting.
	 *
	 * @param name the name of the setting
	 * @param <T> the type of the setting
	 * @return the value of the setting, or {@code null} if not available
	 */
	@SuppressWarnings("unchecked")
	public <T> T setting(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) this.settings.get(name);
	}

	/**
	 * Sets a configuration setting.
	 *
	 * @param name the name of the setting
	 * @param value the value of the setting
	 * @param <T> the type of the {@link Settings}
	 * @return the {@link Settings}
	 */
	@SuppressWarnings("unchecked")
	public <T extends Settings> T setting(String name, Object value) {
		Assert.hasText(name, "name cannot be empty");
		Assert.notNull(value, "value cannot be null");
		this.settings.put(name, value);
		return (T) this;
	}

	/**
	 * Returns a {@code Map} of the configuration settings.
	 *
	 * @return a {@code Map} of the configuration settings
	 */
	public Map<String, Object> settings() {
		return this.settings;
	}

	/**
	 * A {@code Consumer} of the configuration settings {@code Map}
	 * allowing the ability to add, replace, or remove.
	 *
	 * @param settingsConsumer a {@link Consumer} of the configuration settings {@code Map}
	 * @param <T> the type of the {@link Settings}
	 * @return the {@link Settings}
	 */
	@SuppressWarnings("unchecked")
	public <T extends Settings> T settings(Consumer<Map<String, Object>> settingsConsumer) {
		settingsConsumer.accept(this.settings);
		return (T) this;
	}
}
