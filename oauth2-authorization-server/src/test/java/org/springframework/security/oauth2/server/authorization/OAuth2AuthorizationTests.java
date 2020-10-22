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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2Authorization}.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 */
public class OAuth2AuthorizationTests {
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final String PRINCIPAL_NAME = "principal";
	private static final OAuth2AccessToken ACCESS_TOKEN = new OAuth2AccessToken(
			OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now(), Instant.now().plusSeconds(300));
	private static final OAuth2AuthorizationCode AUTHORIZATION_CODE = new OAuth2AuthorizationCode(
			"code", Instant.now(), Instant.now().plus(5, ChronoUnit.MINUTES));

	@Test
	public void withRegisteredClientWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Authorization.withRegisteredClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClient cannot be null");
	}

	@Test
	public void fromWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Authorization.from(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization cannot be null");
	}

	@Test
	public void fromWhenAuthorizationProvidedThenCopied() {
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.tokens(OAuth2Tokens.builder().token(AUTHORIZATION_CODE).accessToken(ACCESS_TOKEN).build())
				.build();
		OAuth2Authorization authorizationResult = OAuth2Authorization.from(authorization).build();

		assertThat(authorizationResult.getRegisteredClientId()).isEqualTo(authorization.getRegisteredClientId());
		assertThat(authorizationResult.getPrincipalName()).isEqualTo(authorization.getPrincipalName());
		assertThat(authorizationResult.getTokens().getAccessToken()).isEqualTo(authorization.getTokens().getAccessToken());
		assertThat(authorizationResult.getTokens().getToken(OAuth2AuthorizationCode.class))
				.isEqualTo(authorization.getTokens().getToken(OAuth2AuthorizationCode.class));
		assertThat(authorizationResult.getAttributes()).isEqualTo(authorization.getAttributes());
	}

	@Test
	public void buildWhenPrincipalNameNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principalName cannot be empty");
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
				.tokens(OAuth2Tokens.builder().token(AUTHORIZATION_CODE).accessToken(ACCESS_TOKEN).build())
				.build();

		assertThat(authorization.getRegisteredClientId()).isEqualTo(REGISTERED_CLIENT.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(PRINCIPAL_NAME);
		assertThat(authorization.getTokens().getToken(OAuth2AuthorizationCode.class)).isEqualTo(AUTHORIZATION_CODE);
		assertThat(authorization.getTokens().getAccessToken()).isEqualTo(ACCESS_TOKEN);
	}
}
