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

import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizationCodeAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeAuthenticationTokenTests {
	private String code = "code";
	private OAuth2ClientAuthenticationToken clientPrincipal =
			new OAuth2ClientAuthenticationToken(TestRegisteredClients.registeredClient().build());
	private String clientId = "clientId";
	private String redirectUri = "redirectUri";

	@Test
	public void constructorWhenCodeNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(null, this.clientPrincipal, this.redirectUri))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("code cannot be empty");
	}

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(this.code, (Authentication) null, this.redirectUri))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenClientIdNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(this.code, (String) null, this.redirectUri))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientId cannot be empty");
	}

	@Test
	public void constructorWhenClientPrincipalProvidedThenCreated() {
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				this.code, this.clientPrincipal, this.redirectUri);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getCode()).isEqualTo(this.code);
		assertThat(authentication.getRedirectUri()).isEqualTo(this.redirectUri);
	}

	@Test
	public void constructorWhenClientIdProvidedThenCreated() {
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				this.code, this.clientId, this.redirectUri);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientId);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getCode()).isEqualTo(this.code);
		assertThat(authentication.getRedirectUri()).isEqualTo(this.redirectUri);
	}
}
