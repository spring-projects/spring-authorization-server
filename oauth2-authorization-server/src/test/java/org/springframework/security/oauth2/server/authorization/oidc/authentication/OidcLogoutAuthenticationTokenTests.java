/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.sql.Date;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.session.SessionInformation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcLogoutAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OidcLogoutAuthenticationTokenTests {
	private final String idToken = "id-token";
	private final TestingAuthenticationToken principal = new TestingAuthenticationToken("principal", "credentials");
	private final String sessionId = "session-1";
	private final SessionInformation sessionInformation = new SessionInformation(this.principal, "session-2", Date.from(Instant.now()));
	private final String clientId = "client-1";
	private final String postLogoutRedirectUri = "https://example.com/oidc-post-logout";
	private final String state = "state-1";

	@Test
	public void constructorWhenIdTokenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcLogoutAuthenticationToken(
						null, this.principal, this.sessionId, this.clientId, this.postLogoutRedirectUri, this.state))
				.withMessage("idToken cannot be empty");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcLogoutAuthenticationToken(
						null, this.principal, this.sessionInformation, this.clientId, this.postLogoutRedirectUri, this.state))
				.withMessage("idToken cannot be empty");
	}

	@Test
	public void constructorWhenIdTokenEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcLogoutAuthenticationToken(
						"", this.principal, this.sessionId, this.clientId, this.postLogoutRedirectUri, this.state))
				.withMessage("idToken cannot be empty");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcLogoutAuthenticationToken(
						"", this.principal, this.sessionInformation, this.clientId, this.postLogoutRedirectUri, this.state))
				.withMessage("idToken cannot be empty");
	}

	@Test
	public void constructorWhenPrincipalNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcLogoutAuthenticationToken(
						this.idToken, null, this.sessionId, this.clientId, this.postLogoutRedirectUri, this.state))
				.withMessage("principal cannot be null");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OidcLogoutAuthenticationToken(
						this.idToken, null, this.sessionInformation, this.clientId, this.postLogoutRedirectUri, this.state))
				.withMessage("principal cannot be null");
	}

	@Test
	public void constructorWhenSessionIdProvidedThenCreated() {
		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(
				this.idToken, this.principal, this.sessionId, this.clientId, this.postLogoutRedirectUri, this.state);
		assertThat(authentication.getPrincipal()).isEqualTo(this.principal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getIdToken()).isEqualTo(this.idToken);
		assertThat(authentication.getSessionId()).isEqualTo(this.sessionId);
		assertThat(authentication.getSessionInformation()).isNull();
		assertThat(authentication.getClientId()).isEqualTo(this.clientId);
		assertThat(authentication.getPostLogoutRedirectUri()).isEqualTo(this.postLogoutRedirectUri);
		assertThat(authentication.getState()).isEqualTo(this.state);
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void constructorWhenSessionInformationProvidedThenCreated() {
		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken(
				this.idToken, this.principal, this.sessionInformation, this.clientId, this.postLogoutRedirectUri, this.state);
		assertThat(authentication.getPrincipal()).isEqualTo(this.principal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getIdToken()).isEqualTo(this.idToken);
		assertThat(authentication.getSessionId()).isEqualTo(this.sessionInformation.getSessionId());
		assertThat(authentication.getSessionInformation()).isEqualTo(this.sessionInformation);
		assertThat(authentication.getClientId()).isEqualTo(this.clientId);
		assertThat(authentication.getPostLogoutRedirectUri()).isEqualTo(this.postLogoutRedirectUri);
		assertThat(authentication.getState()).isEqualTo(this.state);
		assertThat(authentication.isAuthenticated()).isTrue();
	}

}
