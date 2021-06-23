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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeRequestAuthenticationTokenTests {
	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorize";
	private static final String STATE = "state";
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final TestingAuthenticationToken PRINCIPAL = new TestingAuthenticationToken("principalName", "password");
	private static final OAuth2AuthorizationCode AUTHORIZATION_CODE =
			new OAuth2AuthorizationCode("code", Instant.now(), Instant.now().plus(5, ChronoUnit.MINUTES));

	@Test
	public void withWhenClientIdNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizationCodeRequestAuthenticationToken.with(null, PRINCIPAL))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientId cannot be empty");
	}

	@Test
	public void withWhenPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AuthorizationCodeRequestAuthenticationToken.with(REGISTERED_CLIENT.getClientId(), null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principal cannot be null");
	}

	@Test
	public void buildWhenAuthorizationUriNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(REGISTERED_CLIENT.getClientId(), PRINCIPAL)
						.build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationUri cannot be empty");
	}

	@Test
	public void buildWhenStateNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(REGISTERED_CLIENT.getClientId(), PRINCIPAL)
						.authorizationUri(AUTHORIZATION_URI)
						.consent(true)
						.build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("state cannot be empty");
	}

	@Test
	public void buildWhenAuthorizationCodeRequestThenValuesAreSet() {
		String clientId = REGISTERED_CLIENT.getClientId();
		String redirectUri = REGISTERED_CLIENT.getRedirectUris().iterator().next();
		Set<String> requestedScopes = REGISTERED_CLIENT.getScopes();
		Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(clientId, PRINCIPAL)
						.authorizationUri(AUTHORIZATION_URI)
						.redirectUri(redirectUri)
						.scopes(requestedScopes)
						.state(STATE)
						.additionalParameters(additionalParameters)
						.build();

		assertThat(authentication.getPrincipal()).isEqualTo(PRINCIPAL);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEmpty();
		assertThat(authentication.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(clientId);
		assertThat(authentication.getRedirectUri()).isEqualTo(redirectUri);
		assertThat(authentication.getScopes()).containsExactlyInAnyOrderElementsOf(requestedScopes);
		assertThat(authentication.getState()).isEqualTo(STATE);
		assertThat(authentication.getAdditionalParameters()).containsExactlyInAnyOrderEntriesOf(additionalParameters);
		assertThat(authentication.isConsentRequired()).isFalse();
		assertThat(authentication.isConsent()).isFalse();
		assertThat(authentication.getAuthorizationCode()).isNull();
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void buildWhenAuthorizationConsentRequiredThenValuesAreSet() {
		String clientId = REGISTERED_CLIENT.getClientId();
		Set<String> authorizedScopes = REGISTERED_CLIENT.getScopes();

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(clientId, PRINCIPAL)
						.authorizationUri(AUTHORIZATION_URI)
						.scopes(authorizedScopes)
						.state(STATE)
						.consentRequired(true)
						.build();

		assertThat(authentication.getPrincipal()).isEqualTo(PRINCIPAL);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEmpty();
		assertThat(authentication.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(clientId);
		assertThat(authentication.getRedirectUri()).isNull();
		assertThat(authentication.getScopes()).containsExactlyInAnyOrderElementsOf(authorizedScopes);
		assertThat(authentication.getState()).isEqualTo(STATE);
		assertThat(authentication.getAdditionalParameters()).isEmpty();
		assertThat(authentication.isConsentRequired()).isTrue();
		assertThat(authentication.isConsent()).isFalse();
		assertThat(authentication.getAuthorizationCode()).isNull();
		assertThat(authentication.isAuthenticated()).isTrue();
	}

	@Test
	public void buildWhenAuthorizationConsentRequestThenValuesAreSet() {
		String clientId = REGISTERED_CLIENT.getClientId();
		Set<String> authorizedScopes = REGISTERED_CLIENT.getScopes();
		Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(clientId, PRINCIPAL)
						.authorizationUri(AUTHORIZATION_URI)
						.scopes(authorizedScopes)
						.state(STATE)
						.additionalParameters(additionalParameters)
						.consent(true)
						.build();

		assertThat(authentication.getPrincipal()).isEqualTo(PRINCIPAL);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEmpty();
		assertThat(authentication.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(clientId);
		assertThat(authentication.getRedirectUri()).isNull();
		assertThat(authentication.getScopes()).containsExactlyInAnyOrderElementsOf(authorizedScopes);
		assertThat(authentication.getState()).isEqualTo(STATE);
		assertThat(authentication.getAdditionalParameters()).containsExactlyInAnyOrderEntriesOf(additionalParameters);
		assertThat(authentication.isConsentRequired()).isFalse();
		assertThat(authentication.isConsent()).isTrue();
		assertThat(authentication.getAuthorizationCode()).isNull();
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void buildWhenAuthorizationResponseThenValuesAreSet() {
		String clientId = REGISTERED_CLIENT.getClientId();
		String redirectUri = REGISTERED_CLIENT.getRedirectUris().iterator().next();
		Set<String> authorizedScopes = REGISTERED_CLIENT.getScopes();

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(clientId, PRINCIPAL)
						.authorizationUri(AUTHORIZATION_URI)
						.redirectUri(redirectUri)
						.scopes(authorizedScopes)
						.state(STATE)
						.authorizationCode(AUTHORIZATION_CODE)
						.build();

		assertThat(authentication.getPrincipal()).isEqualTo(PRINCIPAL);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEmpty();
		assertThat(authentication.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(clientId);
		assertThat(authentication.getRedirectUri()).isEqualTo(redirectUri);
		assertThat(authentication.getScopes()).containsExactlyInAnyOrderElementsOf(authorizedScopes);
		assertThat(authentication.getState()).isEqualTo(STATE);
		assertThat(authentication.getAdditionalParameters()).isEmpty();
		assertThat(authentication.isConsentRequired()).isFalse();
		assertThat(authentication.isConsent()).isFalse();
		assertThat(authentication.getAuthorizationCode()).isEqualTo(AUTHORIZATION_CODE);
		assertThat(authentication.isAuthenticated()).isTrue();
	}

}
