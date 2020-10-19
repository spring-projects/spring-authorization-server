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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link InMemoryOAuth2AuthorizationService}.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 */
public class InMemoryOAuth2AuthorizationServiceTests {
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final String PRINCIPAL_NAME = "principal";
	private static final String AUTHORIZATION_CODE = "code";
	private InMemoryOAuth2AuthorizationService authorizationService;

	@Before
	public void setup() {
		this.authorizationService = new InMemoryOAuth2AuthorizationService();
	}

	@Test
	public void saveWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.save(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization cannot be null");
	}

	@Test
	public void saveWhenAuthorizationProvidedThenSaved() {
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.CODE, AUTHORIZATION_CODE)
				.build();
		this.authorizationService.save(expectedAuthorization);

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE, TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isEqualTo(expectedAuthorization);
	}

	@Test
	public void removeWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.remove(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization cannot be null");
	}

	@Test
	public void removeWhenAuthorizationProvidedThenRemoved() {
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.CODE, AUTHORIZATION_CODE)
				.build();

		this.authorizationService.save(expectedAuthorization);
		OAuth2Authorization authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE, TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isEqualTo(expectedAuthorization);

		this.authorizationService.remove(expectedAuthorization);
		authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE, TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isNull();
	}

	@Test
	public void findByTokenWhenTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.findByToken(null, TokenType.AUTHORIZATION_CODE))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be empty");
	}

	@Test
	public void findByTokenWhenTokenTypeStateThenFound() {
		String state = "state";
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.STATE, state)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				state, new TokenType(OAuth2AuthorizationAttributeNames.STATE));
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenTokenTypeAuthorizationCodeThenFound() {
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.CODE, AUTHORIZATION_CODE)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				AUTHORIZATION_CODE, TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenTokenTypeAccessTokenThenFound() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token", Instant.now().minusSeconds(60), Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.CODE, AUTHORIZATION_CODE)
				.tokens(OAuth2Tokens.builder().accessToken(accessToken).build())
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				"access-token", TokenType.ACCESS_TOKEN);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenTokenDoesNotExistThenNull() {
		OAuth2Authorization result = this.authorizationService.findByToken(
				"access-token", TokenType.ACCESS_TOKEN);
		assertThat(result).isNull();
	}
}
