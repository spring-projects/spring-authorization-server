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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ProviderSettings}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ProviderSettingsTests {

	@Test
	public void buildWhenDefaultThenDefaultsAreSet() {
		ProviderSettings providerSettings = ProviderSettings.builder().build();

		assertThat(providerSettings.getIssuer()).isNull();
		assertThat(providerSettings.getAuthorizationEndpoint()).isEqualTo("/oauth2/authorize");
		assertThat(providerSettings.getTokenEndpoint()).isEqualTo("/oauth2/token");
		assertThat(providerSettings.getJwkSetEndpoint()).isEqualTo("/oauth2/jwks");
		assertThat(providerSettings.getTokenRevocationEndpoint()).isEqualTo("/oauth2/revoke");
		assertThat(providerSettings.getTokenIntrospectionEndpoint()).isEqualTo("/oauth2/introspect");
		assertThat(providerSettings.getOidcClientRegistrationEndpoint()).isEqualTo("/connect/register");
		assertThat(providerSettings.getOidcUserInfoEndpoint()).isEqualTo("/userinfo");
	}

	@Test
	public void buildWhenSettingsProvidedThenSet() {
		String authorizationEndpoint = "/oauth2/v1/authorize";
		String tokenEndpoint = "/oauth2/v1/token";
		String jwkSetEndpoint = "/oauth2/v1/jwks";
		String tokenRevocationEndpoint = "/oauth2/v1/revoke";
		String tokenIntrospectionEndpoint = "/oauth2/v1/introspect";
		String oidcClientRegistrationEndpoint = "/connect/v1/register";
		String oidcUserInfoEndpoint = "/connect/v1/userinfo";
		String issuer = "https://example.com:9000";

		ProviderSettings providerSettings = ProviderSettings.builder()
				.issuer(issuer)
				.authorizationEndpoint(authorizationEndpoint)
				.tokenEndpoint(tokenEndpoint)
				.jwkSetEndpoint(jwkSetEndpoint)
				.tokenRevocationEndpoint(tokenRevocationEndpoint)
				.tokenIntrospectionEndpoint(tokenIntrospectionEndpoint)
				.tokenRevocationEndpoint(tokenRevocationEndpoint)
				.oidcClientRegistrationEndpoint(oidcClientRegistrationEndpoint)
				.oidcUserInfoEndpoint(oidcUserInfoEndpoint)
				.build();

		assertThat(providerSettings.getIssuer()).isEqualTo(issuer);
		assertThat(providerSettings.getAuthorizationEndpoint()).isEqualTo(authorizationEndpoint);
		assertThat(providerSettings.getTokenEndpoint()).isEqualTo(tokenEndpoint);
		assertThat(providerSettings.getJwkSetEndpoint()).isEqualTo(jwkSetEndpoint);
		assertThat(providerSettings.getTokenRevocationEndpoint()).isEqualTo(tokenRevocationEndpoint);
		assertThat(providerSettings.getTokenIntrospectionEndpoint()).isEqualTo(tokenIntrospectionEndpoint);
		assertThat(providerSettings.getOidcClientRegistrationEndpoint()).isEqualTo(oidcClientRegistrationEndpoint);
		assertThat(providerSettings.getOidcUserInfoEndpoint()).isEqualTo(oidcUserInfoEndpoint);
	}

	@Test
	public void settingWhenCustomThenSet() {
		ProviderSettings providerSettings = ProviderSettings.builder()
				.setting("name1", "value1")
				.settings(settings -> settings.put("name2", "value2"))
				.build();

		assertThat(providerSettings.getSettings()).hasSize(9);
		assertThat(providerSettings.<String>getSetting("name1")).isEqualTo("value1");
		assertThat(providerSettings.<String>getSetting("name2")).isEqualTo("value2");
	}

	@Test
	public void issuerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().issuer(null))
				.withMessage("value cannot be null");
	}

	@Test
	public void authorizationEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().authorizationEndpoint(null))
				.withMessage("value cannot be null");
	}

	@Test
	public void tokenEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().tokenEndpoint(null))
				.withMessage("value cannot be null");
	}

	@Test
	public void tokenRevocationEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().tokenRevocationEndpoint(null))
				.withMessage("value cannot be null");
	}

	@Test
	public void tokenIntrospectionEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().tokenIntrospectionEndpoint(null))
				.withMessage("value cannot be null");
	}

	@Test
	public void oidcClientRegistrationEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().oidcClientRegistrationEndpoint(null))
				.withMessage("value cannot be null");
	}

	@Test
	public void oidcUserInfoEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().oidcUserInfoEndpoint(null))
				.withMessage("value cannot be null");
	}

	@Test
	public void jwksEndpointWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ProviderSettings.builder().jwkSetEndpoint(null))
				.withMessage("value cannot be null");
	}

}
