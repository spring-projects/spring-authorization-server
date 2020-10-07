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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * @author Alexey Nesterov
 * @since 0.0.3
 */
public class OAuth2RefreshTokenAuthenticationTokenTests {

	@Test
	public void constructorWhenClientPrincipalNullThrowException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationToken("", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenRefreshTokenNullOrEmptyThrowException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationToken(null, mock(OAuth2ClientAuthenticationToken.class)))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("refreshToken cannot be null or empty");

		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationToken("", mock(OAuth2ClientAuthenticationToken.class)))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("refreshToken cannot be null or empty");
	}

	@Test
	public void constructorWhenGettingScopesThenReturnRequestedScopes() {
		Set<String> expectedScopes = new HashSet<>(Arrays.asList("scope-a", "scope-b"));
		OAuth2RefreshTokenAuthenticationToken token
				= new OAuth2RefreshTokenAuthenticationToken(mock(OAuth2ClientAuthenticationToken.class), "test", expectedScopes);

		assertThat(token.getScopes()).containsAll(expectedScopes);
	}
}
