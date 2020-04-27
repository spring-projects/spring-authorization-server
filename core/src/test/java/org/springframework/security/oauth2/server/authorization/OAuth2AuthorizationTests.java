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

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests For {@link OAuth2Authorization}.
 *
 * @author Krisztian Toth
 */
public class OAuth2AuthorizationTests {

	public static final String REGISTERED_CLIENT_ID = "clientId";
	public static final String PRINCIPAL_NAME = "principal";
	public static final OAuth2AccessToken ACCESS_TOKEN = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
			"token", Instant.now().minusSeconds(60), Instant.now());
	public static final String AUTHORIZATION_CODE_VALUE = TokenType.AUTHORIZATION_CODE.getValue();
	public static final String CODE = "code";
	public static final Map<String, Object> ATTRIBUTES = Collections.singletonMap(AUTHORIZATION_CODE_VALUE, CODE);

	@Test
	public void buildWhenAllAttributesAreProvidedThenAllAttributesAreSet() {
		OAuth2Authorization authorization = OAuth2Authorization.builder()
				.registeredClientId(REGISTERED_CLIENT_ID)
				.principalName(PRINCIPAL_NAME)
				.accessToken(ACCESS_TOKEN)
				.attribute(AUTHORIZATION_CODE_VALUE, CODE)
				.build();

		assertThat(authorization.getRegisteredClientId()).isEqualTo(REGISTERED_CLIENT_ID);
		assertThat(authorization.getPrincipalName()).isEqualTo(PRINCIPAL_NAME);
		assertThat(authorization.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		assertThat(authorization.getAttributes()).isEqualTo(ATTRIBUTES);
	}

	@Test
	public void buildWhenBuildThenImmutableMapIsCreated() {
		OAuth2Authorization authorization = OAuth2Authorization.builder()
				.registeredClientId(REGISTERED_CLIENT_ID)
				.principalName(PRINCIPAL_NAME)
				.accessToken(ACCESS_TOKEN)
				.attribute("any", "value")
				.build();

		assertThatThrownBy(() -> authorization.getAttributes().put("any", "value"))
				.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void buildWhenAccessTokenAndAuthorizationCodeNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.builder()
						.registeredClientId(REGISTERED_CLIENT_ID)
						.principalName(PRINCIPAL_NAME)
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenRegisteredClientIdNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.builder()
						.principalName(PRINCIPAL_NAME)
						.accessToken(ACCESS_TOKEN)
						.attribute(AUTHORIZATION_CODE_VALUE, CODE)
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenPrincipalNameNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.builder()
						.registeredClientId(REGISTERED_CLIENT_ID)
						.accessToken(ACCESS_TOKEN)
						.attribute(AUTHORIZATION_CODE_VALUE, CODE)
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAttributeSetWithNullNameThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.builder()
						.attribute(null, CODE)
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAttributeSetWithNullValueThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2Authorization.builder()
						.attribute(AUTHORIZATION_CODE_VALUE, null)
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void withOAuth2AuthorizationWhenAuthorizationProvidedThenAllAttributesAreCopied() {
		OAuth2Authorization authorizationToCopy = OAuth2Authorization.builder()
				.registeredClientId(REGISTERED_CLIENT_ID)
				.principalName(PRINCIPAL_NAME)
				.attribute(AUTHORIZATION_CODE_VALUE, CODE)
				.build();

		OAuth2Authorization authorization = OAuth2Authorization.withAuthorization(authorizationToCopy)
				.accessToken(ACCESS_TOKEN)
				.build();

		assertThat(authorization.getRegisteredClientId()).isEqualTo(REGISTERED_CLIENT_ID);
		assertThat(authorization.getPrincipalName()).isEqualTo(PRINCIPAL_NAME);
		assertThat(authorization.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		assertThat(authorization.getAttributes()).isEqualTo(ATTRIBUTES);
	}
}
