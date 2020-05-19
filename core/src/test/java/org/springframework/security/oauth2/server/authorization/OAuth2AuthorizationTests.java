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
package org.springframework.security.oauth2.server.authorization;

import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.data.MapEntry.entry;

/**
 * Tests for {@link OAuth2Authorization}.
 *
 * @author Krisztian Toth
 */
public class OAuth2AuthorizationTests {
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final String PRINCIPAL_NAME = "principal";
	private static final OAuth2AccessToken ACCESS_TOKEN = new OAuth2AccessToken(
			OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now().minusSeconds(60), Instant.now());
	private static final String AUTHORIZATION_CODE = "code";

	@Test
	public void withRegisteredClientWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Authorization.withRegisteredClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClient cannot be null");
	}

	@Test
	public void buildWhenPrincipalNameNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principalName cannot be empty");
	}

	@Test
	public void buildWhenAuthorizationCodeNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
						.principalName(PRINCIPAL_NAME).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization code cannot be null");
	}

	@Test
	public void attributeWhenNameNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
						.attribute(null, AUTHORIZATION_CODE))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void attributeWhenValueNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
						.attribute(TokenType.AUTHORIZATION_CODE.getValue(), null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void buildWhenAllAttributesAreProvidedThenAllAttributesAreSet() {
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.accessToken(ACCESS_TOKEN)
				.attribute(OAuth2ParameterNames.class.getName().concat(".CODE"), AUTHORIZATION_CODE)
				.build();

		assertThat(authorization.getRegisteredClientId()).isEqualTo(REGISTERED_CLIENT.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(PRINCIPAL_NAME);
		assertThat(authorization.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		assertThat(authorization.getAttributes()).containsExactly(
				entry(OAuth2ParameterNames.class.getName().concat(".CODE"), AUTHORIZATION_CODE));
	}
}
