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
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ClientSettings}.
 *
 * @author Joe Grandja
 */
public class ClientSettingsTests {

	@Test
	public void buildWhenDefaultThenDefaultsAreSet() {
		ClientSettings clientSettings = ClientSettings.builder().build();
		assertThat(clientSettings.getSettings()).hasSize(3);
		assertThat(clientSettings.isRequireProofKey()).isFalse();
		assertThat(clientSettings.isRequireAuthorizationConsent()).isFalse();
		assertThat(clientSettings.getTokenEndpointSigningAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);
	}

	@Test
	public void requireProofKeyWhenTrueThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
				.requireProofKey(true)
				.build();
		assertThat(clientSettings.isRequireProofKey()).isTrue();
	}

	@Test
	public void requireAuthorizationConsentWhenTrueThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
				.requireAuthorizationConsent(true)
				.build();
		assertThat(clientSettings.isRequireAuthorizationConsent()).isTrue();
	}

	@Test
	public void tokenEndpointAlgorithmWhenHS256ThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
				.tokenEndpointSigningAlgorithm(MacAlgorithm.HS256)
				.build();
		assertThat(clientSettings.getTokenEndpointSigningAlgorithm()).isEqualTo(MacAlgorithm.HS256);
	}

	@Test
	public void whenJwkSetUrlSetThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
				.jwkSetUrl("https://auth-server:9000/jwks")
				.build();
		assertThat(clientSettings.getJwkSetUrl()).isEqualTo("https://auth-server:9000/jwks");
	}

	@Test
	public void settingWhenCustomThenSet() {
		ClientSettings clientSettings = ClientSettings.builder()
				.setting("name1", "value1")
				.settings(settings -> settings.put("name2", "value2"))
				.build();
		assertThat(clientSettings.getSettings()).hasSize(5);
		assertThat(clientSettings.<String>getSetting("name1")).isEqualTo("value1");
		assertThat(clientSettings.<String>getSetting("name2")).isEqualTo("value2");
	}

}
