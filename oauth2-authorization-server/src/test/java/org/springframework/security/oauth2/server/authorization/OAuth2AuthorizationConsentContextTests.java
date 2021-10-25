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
package org.springframework.security.oauth2.server.authorization;

import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizationConsentContext}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationConsentContextTests {

	@Test
	public void withWhenAuthorizationConsentBuilderNullThenIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizationConsentContext.with(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationConsentBuilder cannot be null");
	}

	@Test
	public void setWhenValueNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationConsentContext.Builder builder = OAuth2AuthorizationConsentContext
				.with(OAuth2AuthorizationConsent.withId("some-client", "some-principal"));
		assertThatThrownBy(() -> builder.principal(null))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.registeredClient(null))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.authorization(null))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.authorizationRequest(null))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.put(null, ""))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAllValuesProvidedThenAllValuesAreSet() {
		OAuth2AuthorizationConsent.Builder authorizationConsentBuilder = OAuth2AuthorizationConsent
				.withId("some-client", "some-principal");
		TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "password");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with("test-client", principal)
						.authorizationUri("https://provider.com/oauth2/authorize")
						.build();
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationRequest.class.getName());

		OAuth2AuthorizationConsentContext context = OAuth2AuthorizationConsentContext
				.with(authorizationConsentBuilder)
				.principal(authentication)
				.registeredClient(registeredClient)
				.authorization(authorization)
				.authorizationRequest(authorizationRequest)
				.put("custom-key-1", "custom-value-1")
				.context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
				.build();

		assertThat(context.getAuthorizationConsentBuilder()).isEqualTo(authorizationConsentBuilder);
		assertThat(context.<OAuth2AuthorizationCodeRequestAuthenticationToken>getPrincipal()).isEqualTo(authentication);
		assertThat(context.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(context.getAuthorization()).isEqualTo(authorization);
		assertThat(context.getAuthorizationRequest()).isEqualTo(authorizationRequest);
		assertThat(context.<String>get("custom-key-1")).isEqualTo("custom-value-1");
		assertThat(context.<String>get("custom-key-2")).isEqualTo("custom-value-2");
	}
}