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
 * Tests for {@link ProviderSettings}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ProviderSettingsTests {

	@Test
	public void constructorWhenDefaultThenDefaultsAreSet() {
		ProviderSettings providerSettings = new ProviderSettings();

		assertThat(providerSettings.issuer()).isNull();
		assertThat(providerSettings.authorizationEndpoint()).isEqualTo("/oauth2/authorize");
		assertThat(providerSettings.tokenEndpoint()).isEqualTo("/oauth2/token");
		assertThat(providerSettings.jwkSetEndpoint()).isEqualTo("/oauth2/jwks");
		assertThat(providerSettings.tokenRevocationEndpoint()).isEqualTo("/oauth2/revoke");
		assertThat(providerSettings.tokenIntrospectionEndpoint()).isEqualTo("/oauth2/introspect");
	}

	@Test
	public void settingsWhenProvidedThenSet() {
		String authorizationEndpoint = "/oauth2/v1/authorize";
		String tokenEndpoint = "/oauth2/v1/token";
		String jwkSetEndpoint = "/oauth2/v1/jwks";
		String tokenRevocationEndpoint = "/oauth2/v1/revoke";
		String tokenIntrospectionEndpoint = "/oauth2/v1/introspect";
		String issuer = "https://example.com:9000";

		ProviderSettings providerSettings = new ProviderSettings()
				.issuer(issuer)
				.authorizationEndpoint(authorizationEndpoint)
				.tokenEndpoint(tokenEndpoint)
				.jwkSetEndpoint(jwkSetEndpoint)
				.tokenRevocationEndpoint(tokenRevocationEndpoint)
				.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint);

		assertThat(providerSettings.issuer()).isEqualTo(issuer);
		assertThat(providerSettings.authorizationEndpoint()).isEqualTo(authorizationEndpoint);
		assertThat(providerSettings.tokenEndpoint()).isEqualTo(tokenEndpoint);
		assertThat(providerSettings.jwkSetEndpoint()).isEqualTo(jwkSetEndpoint);
		assertThat(providerSettings.tokenRevocationEndpoint()).isEqualTo(tokenRevocationEndpoint);
		assertThat(providerSettings.tokenIntrospectionEndpoint()).isEqualTo(tokenIntrospectionEndpoint);
	}

	@Test
	public void settingWhenCustomThenReturnAllSettings() {
		ProviderSettings providerSettings = new ProviderSettings()
				.setting("name1", "value1")
				.settings(settings -> settings.put("name2", "value2"));

		assertThat(providerSettings.settings()).hasSize(7);
		assertThat(providerSettings.<String>setting("name1")).isEqualTo("value1");
		assertThat(providerSettings.<String>setting("name2")).isEqualTo("value2");
	}

	@Test
	public void issuerWhenNullThenThrowIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.issuer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void authorizationEndpointWhenNullThenThrowIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.authorizationEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void tokenEndpointWhenNullThenThrowIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.tokenEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void tokenRevocationEndpointWhenNullThenThrowIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.tokenRevocationEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void tokenIntrospectionEndpointWhenNullThenThrowIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.tokenIntrospectionEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void jwksEndpointWhenNullThenThrowIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.jwkSetEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}
}
