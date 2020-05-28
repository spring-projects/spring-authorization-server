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
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultOAuth2TokenRevocationService}.
 *
 * @author Vivek Babu
 */
public class DefaultOAuth2TokenRevocationServiceTests {
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final String PRINCIPAL_NAME = "principal";
	private static final String AUTHORIZATION_CODE = "code";
	private DefaultOAuth2TokenRevocationService revocationService;
	private OAuth2AuthorizationService authorizationService;

	@Before
	public void setup() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.revocationService = new DefaultOAuth2TokenRevocationService(authorizationService);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DefaultOAuth2TokenRevocationService(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void revokeWhenTokenNotFound() {
		this.revocationService.revoke("token", TokenType.ACCESS_TOKEN);
		verify(authorizationService, times(1)).findByTokenAndTokenType(eq("token"),
				eq(TokenType.ACCESS_TOKEN));
		verify(authorizationService, times(0)).save(any());
	}

	@Test
	public void revokeWhenTokenFound() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"token", Instant.now().minusSeconds(60), Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.CODE, AUTHORIZATION_CODE)
				.accessToken(accessToken)
				.build();
		when(authorizationService.findByTokenAndTokenType(eq("token"), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		this.revocationService.revoke("token", TokenType.ACCESS_TOKEN);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		final OAuth2Authorization savedAuthorization = authorizationCaptor.getValue();
		assertThat(savedAuthorization.getPrincipalName()).isEqualTo(authorization.getPrincipalName());
		assertThat((String) savedAuthorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE))
				.isEqualTo(authorization.getAttribute(OAuth2AuthorizationAttributeNames.CODE));
		assertThat(savedAuthorization.getAccessToken()).isEqualTo(authorization.getAccessToken());
		assertThat(savedAuthorization.getRegisteredClientId()).isEqualTo(authorization.getRegisteredClientId());
		assertThat(savedAuthorization.isRevoked()).isTrue();
	}
}
