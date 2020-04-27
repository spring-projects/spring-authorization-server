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
import java.util.ArrayList;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryOAuth2AuthorizationService}.
 *
 * @author Krisztian Toth
 */
public class InMemoryOAuth2AuthorizationServiceTests {

	private static final String TOKEN = "token";
	private static final TokenType AUTHORIZATION_CODE = TokenType.AUTHORIZATION_CODE;
	private static final TokenType ACCESS_TOKEN = TokenType.ACCESS_TOKEN;
	private static final Instant ISSUED_AT = Instant.now().minusSeconds(60);
	private static final Instant EXPIRES_AT = Instant.now();

	private InMemoryOAuth2AuthorizationService authorizationService;

	@Test
	public void saveWhenAuthorizationProvidedThenSavedInList() {
		authorizationService = new InMemoryOAuth2AuthorizationService(new ArrayList<>());

		OAuth2Authorization authorization = OAuth2Authorization.builder()
				.registeredClientId("clientId")
				.principalName("principalName")
				.attribute(AUTHORIZATION_CODE.getValue(), TOKEN)
				.build();
		authorizationService.save(authorization);

		assertThat(authorizationService.findByTokenAndTokenType(TOKEN, AUTHORIZATION_CODE)).isEqualTo(authorization);
	}

	@Test
	public void saveWhenAuthorizationNotProvidedThenThrowIllegalArgumentException() {
		authorizationService = new InMemoryOAuth2AuthorizationService(new ArrayList<>());

		assertThatThrownBy(() -> authorizationService.save(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void findByTokenAndTokenTypeWhenTokenTypeIsAuthorizationCodeThenFound() {
		OAuth2Authorization authorization = OAuth2Authorization.builder()
				.registeredClientId("clientId")
				.principalName("principalName")
				.attribute(AUTHORIZATION_CODE.getValue(), TOKEN)
				.build();
		authorizationService = new InMemoryOAuth2AuthorizationService(Collections.singletonList(authorization));

		OAuth2Authorization result = authorizationService.findByTokenAndTokenType(TOKEN, TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenAndTokenTypeWhenTokenTypeIsAccessTokenThenFound() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, TOKEN, ISSUED_AT,
				EXPIRES_AT);
		OAuth2Authorization authorization = OAuth2Authorization.builder()
				.registeredClientId("clientId")
				.principalName("principalName")
				.accessToken(accessToken)
				.build();
		authorizationService = new InMemoryOAuth2AuthorizationService(Collections.singletonList(authorization));

		OAuth2Authorization result = authorizationService.findByTokenAndTokenType(TOKEN, ACCESS_TOKEN);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenAndTokenTypeWhenTokenWithTokenTypeDoesNotExistThenNull() {
		OAuth2Authorization authorization = OAuth2Authorization.builder()
				.registeredClientId("clientId")
				.principalName("principalName")
				.attribute(AUTHORIZATION_CODE.getValue(), TOKEN)
				.build();
		authorizationService = new InMemoryOAuth2AuthorizationService(Collections.singletonList(authorization));

		OAuth2Authorization result = authorizationService.findByTokenAndTokenType(TOKEN, ACCESS_TOKEN);
		assertThat(result).isNull();
	}

	@Test
	public void findByTokenAndTokenTypeWhenTokenNullThenThrowIllegalArgumentException() {
		authorizationService = new InMemoryOAuth2AuthorizationService();
		assertThatThrownBy(() -> authorizationService.findByTokenAndTokenType(null, TokenType.AUTHORIZATION_CODE))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void findByTokenAndTokenTypeWhenTokenTypeNullThenThrowIllegalArgumentException() {
		authorizationService = new InMemoryOAuth2AuthorizationService();
		assertThatThrownBy(() -> authorizationService.findByTokenAndTokenType(TOKEN, null))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
