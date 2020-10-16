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

import java.net.MalformedURLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link ProviderSettings}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ProviderSettingsTests {
	@Test
	public void constructorWhenDefaultThenDefaultsAreSetAndIssuerIsNotSet() {
		ProviderSettings providerSettings = new ProviderSettings();

		assertThat(providerSettings.issuer()).isNull();
		assertThat(providerSettings.authorizationEndpoint()).isEqualTo("/oauth2/authorize");
		assertThat(providerSettings.tokenEndpoint()).isEqualTo("/oauth2/token");
		assertThat(providerSettings.jwkSetEndpoint()).isEqualTo("/oauth2/jwks");
		assertThat(providerSettings.tokenRevocationEndpoint()).isEqualTo("/oauth2/revoke");
	}

	@Test
	public void settingsWhenProvidedThenSet() throws MalformedURLException {
		String authorizationEndpoint = "/my-endpoints/authorize";
		String tokenEndpoint = "/my-endpoints/token";
		String jwksEndpoint = "/my-endpoints/jwks";
		String tokenRevocationEndpoint = "/my-endpoints/revoke";
		String issuer = "https://example.com/9000";

		ProviderSettings providerSettings = new ProviderSettings()
				.issuer(issuer)
				.authorizationEndpoint(authorizationEndpoint)
				.tokenEndpoint(tokenEndpoint)
				.jwkSetEndpoint(jwksEndpoint)
				.tokenRevocationEndpoint(tokenRevocationEndpoint);

		assertThat(providerSettings.issuer()).isEqualTo(issuer);
		assertThat(providerSettings.authorizationEndpoint()).isEqualTo(authorizationEndpoint);
		assertThat(providerSettings.tokenEndpoint()).isEqualTo(tokenEndpoint);
		assertThat(providerSettings.jwkSetEndpoint()).isEqualTo(jwksEndpoint);
		assertThat(providerSettings.tokenRevocationEndpoint()).isEqualTo(tokenRevocationEndpoint);
	}

	@Test
	public void settingWhenCalledThenReturnTokenSettings() {
		ProviderSettings providerSettings = new ProviderSettings()
				.setting("name1", "value1")
				.settings(settings -> settings.put("name2", "value2"));

		assertThat(providerSettings.settings()).hasSize(6);
		assertThat(providerSettings.<String>setting("name1")).isEqualTo("value1");
		assertThat(providerSettings.<String>setting("name2")).isEqualTo("value2");
	}

	@Test
	public void issuerWhenNullThenThrowsIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.issuer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("issuer cannot be null");
	}

	@Test
	public void authorizationEndpointWhenNullThenThrowsIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.authorizationEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationEndpoint cannot be empty");
		assertThatThrownBy(() -> settings.authorizationEndpoint(""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationEndpoint cannot be empty");
	}

	@Test
	public void tokenEndpointWhenNullThenThrowsIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.tokenEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenEndpoint cannot be empty");
		assertThatThrownBy(() -> settings.tokenEndpoint(""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenEndpoint cannot be empty");
	}

	@Test
	public void tokenRevocationEndpointWhenNullThenThrowsIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.tokenRevocationEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenRevocationEndpoint cannot be empty");
		assertThatThrownBy(() -> settings.tokenRevocationEndpoint(""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenRevocationEndpoint cannot be empty");
	}

	@Test
	public void jwkSetEndpointWhenNullThenThrowsIllegalArgumentException() {
		ProviderSettings settings = new ProviderSettings();
		assertThatThrownBy(() -> settings.jwkSetEndpoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwkSetEndpoint cannot be empty");
		assertThatThrownBy(() -> settings.jwkSetEndpoint(""))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwkSetEndpoint cannot be empty");
	}
}
