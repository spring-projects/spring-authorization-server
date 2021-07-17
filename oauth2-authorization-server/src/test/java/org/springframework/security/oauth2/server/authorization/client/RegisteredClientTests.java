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
package org.springframework.security.oauth2.server.authorization.client;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link RegisteredClient}.
 *
 * @author Anoop Garlapati
 */
public class RegisteredClientTests {
	private static final String ID = "registration-1";
	private static final String CLIENT_ID = "client-1";
	private static final String CLIENT_SECRET = "secret";
	private static final Set<String> REDIRECT_URIS = Collections.singleton("https://example.com");
	private static final Set<String> SCOPES = Collections.unmodifiableSet(
			Stream.of("openid", "profile", "email").collect(Collectors.toSet()));
	private static final Set<ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHODS =
			Collections.singleton(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

	@Test
	public void buildWhenAuthorizationGrantTypesNotSetThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
						.scopes(scopes -> scopes.addAll(SCOPES))
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAllAttributesProvidedThenAllAttributesAreSet() {
		Instant clientIdIssuedAt = Instant.now();
		Instant clientSecretExpiresAt = clientIdIssuedAt.plus(30, ChronoUnit.DAYS);
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientIdIssuedAt(clientIdIssuedAt)
				.clientSecret(CLIENT_SECRET)
				.clientSecretExpiresAt(clientSecretExpiresAt)
				.clientName("client-name")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getId()).isEqualTo(ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientIdIssuedAt()).isEqualTo(clientIdIssuedAt);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getClientSecretExpiresAt()).isEqualTo(clientSecretExpiresAt);
		assertThat(registration.getClientName()).isEqualTo("client-name");
		assertThat(registration.getAuthorizationGrantTypes())
				.isEqualTo(Collections.singleton(AuthorizationGrantType.AUTHORIZATION_CODE));
		assertThat(registration.getClientAuthenticationMethods()).isEqualTo(CLIENT_AUTHENTICATION_METHODS);
		assertThat(registration.getRedirectUris()).isEqualTo(REDIRECT_URIS);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
	}

	@Test
	public void buildWhenIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> RegisteredClient.withId(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenClientIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(null)
						.clientSecret(CLIENT_SECRET)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
						.scopes(scopes -> scopes.addAll(SCOPES))
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenRedirectUrisNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.scopes(scopes -> scopes.addAll(SCOPES))
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenRedirectUrisConsumerClearsSetThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUri("https://example.com")
						.redirectUris(Set::clear)
						.scopes(scopes -> scopes.addAll(SCOPES))
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenClientAuthenticationMethodNotProvidedThenDefaultToBasic() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getClientAuthenticationMethods())
				.isEqualTo(Collections.singleton(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
	}

	@Test
	public void buildWhenScopeIsEmptyThenScopeNotRequired() {
		RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.build();
	}

	@Test
	public void buildWhenScopeConsumerIsProvidedThenConsumerAccepted() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getScopes()).isEqualTo(SCOPES);
	}

	@Test
	public void buildWhenScopeContainsSpaceThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
						.scope("openid profile")
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenScopeContainsInvalidCharacterThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
						.scope("an\"invalid\"scope")
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenRedirectUriInvalidThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUri("invalid URI")
						.scopes(scopes -> scopes.addAll(SCOPES))
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenRedirectUriContainsFragmentThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUri("https://example.com/page#fragment")
						.scopes(scopes -> scopes.addAll(SCOPES))
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenTwoAuthorizationGrantTypesAreProvidedThenBothAreRegistered() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getAuthorizationGrantTypes())
				.containsExactlyInAnyOrder(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS);
	}

	@Test
	public void buildWhenAuthorizationGrantTypesConsumerIsProvidedThenConsumerAccepted() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantTypes(authorizationGrantTypes -> {
					authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
					authorizationGrantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
				})
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getAuthorizationGrantTypes())
				.containsExactlyInAnyOrder(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS);
	}

	@Test
	public void buildWhenAuthorizationGrantTypesConsumerClearsSetThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient.withId(ID)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.authorizationGrantTypes(Set::clear)
					.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
					.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
					.scopes(scopes -> scopes.addAll(SCOPES))
					.build();
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenTwoClientAuthenticationMethodsAreProvidedThenBothAreRegistered() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getClientAuthenticationMethods())
				.containsExactlyInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	@Test
	public void buildWhenBothDeprecatedClientAuthenticationMethodsAreProvidedThenBothNonDeprecatedAreRegistered() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getClientAuthenticationMethods())
				.containsExactlyInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	@Test
	public void buildWhenClientAuthenticationMethodsConsumerIsProvidedThenConsumerAccepted() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethods(clientAuthenticationMethods -> {
					clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
					clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
				})
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getClientAuthenticationMethods())
				.containsExactlyInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	@Test
	public void buildWhenConsumerAddsDeprecatedClientAuthenticationMethodsThenNonDeprecatedAreRegistered() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethods(clientAuthenticationMethods -> {
					clientAuthenticationMethods.add(ClientAuthenticationMethod.BASIC);
					clientAuthenticationMethods.add(ClientAuthenticationMethod.POST);
				})
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getClientAuthenticationMethods())
				.containsExactlyInAnyOrder(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	@Test
	public void buildWhenOverrideIdThenOverridden() {
		String overriddenId = "override";
		RegisteredClient registration = RegisteredClient.withId(ID)
				.id(overriddenId)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getId()).isEqualTo(overriddenId);
	}

	@Test
	public void buildWhenRegisteredClientProvidedThenMakesACopy() {
		RegisteredClient registration = TestRegisteredClients.registeredClient().build();
		RegisteredClient updated = RegisteredClient.from(registration).build();

		assertThat(registration.getId()).isEqualTo(updated.getId());
		assertThat(registration.getClientId()).isEqualTo(updated.getClientId());
		assertThat(registration.getClientIdIssuedAt()).isEqualTo(updated.getClientIdIssuedAt());
		assertThat(registration.getClientSecret()).isEqualTo(updated.getClientSecret());
		assertThat(registration.getClientSecretExpiresAt()).isEqualTo(updated.getClientSecretExpiresAt());
		assertThat(registration.getClientName()).isEqualTo(updated.getClientName());
		assertThat(registration.getClientAuthenticationMethods()).isEqualTo(updated.getClientAuthenticationMethods());
		assertThat(registration.getClientAuthenticationMethods()).isNotSameAs(updated.getClientAuthenticationMethods());
		assertThat(registration.getAuthorizationGrantTypes()).isEqualTo(updated.getAuthorizationGrantTypes());
		assertThat(registration.getAuthorizationGrantTypes()).isNotSameAs(updated.getAuthorizationGrantTypes());
		assertThat(registration.getRedirectUris()).isEqualTo(updated.getRedirectUris());
		assertThat(registration.getRedirectUris()).isNotSameAs(updated.getRedirectUris());
		assertThat(registration.getScopes()).isEqualTo(updated.getScopes());
		assertThat(registration.getScopes()).isNotSameAs(updated.getScopes());
		assertThat(registration.getClientSettings().settings()).isEqualTo(updated.getClientSettings().settings());
		assertThat(registration.getClientSettings()).isNotSameAs(updated.getClientSettings());
		assertThat(registration.getTokenSettings().settings()).isEqualTo(updated.getTokenSettings().settings());
		assertThat(registration.getTokenSettings()).isNotSameAs(updated.getTokenSettings());
	}

	@Test
	public void buildWhenRegisteredClientValuesOverriddenThenPropagated() {
		RegisteredClient registration = TestRegisteredClients.registeredClient().build();
		String newName = "client-name";
		String newSecret = "new-secret";
		String newScope = "new-scope";
		String newRedirectUri = "https://another-redirect-uri.com";
		RegisteredClient updated = RegisteredClient.from(registration)
				.clientName(newName)
				.clientSecret(newSecret)
				.scopes(scopes -> {
					scopes.clear();
					scopes.add(newScope);
				})
				.redirectUris(redirectUris -> {
					redirectUris.clear();
					redirectUris.add(newRedirectUri);
				})
				.build();

		assertThat(registration.getClientName()).isNotEqualTo(newName);
		assertThat(updated.getClientName()).isEqualTo(newName);
		assertThat(registration.getClientSecret()).isNotEqualTo(newSecret);
		assertThat(updated.getClientSecret()).isEqualTo(newSecret);
		assertThat(registration.getScopes()).doesNotContain(newScope);
		assertThat(updated.getScopes()).containsExactly(newScope);
		assertThat(registration.getRedirectUris()).doesNotContain(newRedirectUri);
		assertThat(updated.getRedirectUris()).containsExactly(newRedirectUri);
	}
}
