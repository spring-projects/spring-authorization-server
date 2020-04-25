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
package org.springframework.security.oauth2.server.authorization.client;

import org.junit.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
			Collections.singleton(ClientAuthenticationMethod.BASIC);

	@Test
	public void buildWhenAuthorizationGrantTypesIsNotSetThenThrowIllegalArgumentException() {
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
	public void buildWhenAuthorizationCodeGrantAllAttributesProvidedThenAllAttributesAreSet() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getId()).isEqualTo(ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getAuthorizationGrantTypes())
				.isEqualTo(Collections.singleton(AuthorizationGrantType.AUTHORIZATION_CODE));
		assertThat(registration.getClientAuthenticationMethods()).isEqualTo(CLIENT_AUTHENTICATION_METHODS);
		assertThat(registration.getRedirectUris()).isEqualTo(REDIRECT_URIS);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(null)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
						.scopes(scopes -> scopes.addAll(SCOPES))
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientIdIsNullThenThrowIllegalArgumentException() {
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
	public void buildWhenAuthorizationCodeGrantClientSecretIsNullThenThrowIllegalArgumentException() {
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
	public void buildWhenAuthorizationCodeGrantRedirectUrisNotProvidedThenThrowIllegalArgumentException() {
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
	public void buildWhenAuthorizationCodeGrantRedirectUrisConsumerClearsSetThenThrowIllegalArgumentException() {
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
	public void buildWhenAuthorizationCodeGrantClientAuthenticationMethodNotProvidedThenDefaultToBasic() {
		RegisteredClient registration = RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getClientAuthenticationMethods())
				.isEqualTo(Collections.singleton(ClientAuthenticationMethod.BASIC));
	}

	@Test
	public void buildWhenAuthorizationCodeGrantScopeIsEmptyThenScopeNotRequired() {
		RegisteredClient.withId(ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.build();
	}

	@Test
	public void buildWhenAuthorizationCodeGrantScopeConsumerIsProvidedThenConsumerAccepted() {
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
	public void buildWhenScopeContainsASpaceThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				RegisteredClient.withId(ID)
						.clientId(CLIENT_ID)
						.clientSecret(null)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
						.scope("openid profile")
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenScopesContainsAnInvalidCharacterThenThrowIllegalArgumentException() {
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
	public void buildWhenRedirectUrisContainInvalidUriThenThrowIllegalArgumentException() {
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
	public void buildWhenRedirectUrisContainUriWithFragmentThenThrowIllegalArgumentException() {
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
				.containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS);
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
				.containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS);
	}

	@Test
	public void buildWhenAuthorizationGrantTypesConsumerClearsSetThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient.withId(ID)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
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
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
				.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
				.scopes(scopes -> scopes.addAll(SCOPES))
				.build();

		assertThat(registration.getClientAuthenticationMethods())
				.containsExactly(ClientAuthenticationMethod.BASIC, ClientAuthenticationMethod.POST);
	}

	@Test
	public void buildWhenClientAuthenticationMethodsConsumerIsProvidedThenConsumerAccepted() {
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
				.containsExactly(ClientAuthenticationMethod.BASIC, ClientAuthenticationMethod.POST);
	}

	@Test
	public void buildWhenClientAuthenticationMethodsConsumerClearsSetThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient.withId(ID)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.clientAuthenticationMethods(Set::clear)
					.redirectUris(redirectUris -> redirectUris.addAll(REDIRECT_URIS))
					.scopes(scopes -> scopes.addAll(SCOPES))
					.build();
		}).isInstanceOf(IllegalArgumentException.class);
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
		RegisteredClient updated = RegisteredClient.withRegisteredClient(registration).build();

		assertThat(registration.getClientAuthenticationMethods()).isEqualTo(updated.getClientAuthenticationMethods());
		assertThat(registration.getClientAuthenticationMethods()).isNotSameAs(updated.getClientAuthenticationMethods());
		assertThat(registration.getAuthorizationGrantTypes()).isEqualTo(updated.getAuthorizationGrantTypes());
		assertThat(registration.getAuthorizationGrantTypes()).isNotSameAs(updated.getAuthorizationGrantTypes());
		assertThat(registration.getRedirectUris()).isEqualTo(updated.getRedirectUris());
		assertThat(registration.getRedirectUris()).isNotSameAs(updated.getRedirectUris());
		assertThat(registration.getScopes()).isEqualTo(updated.getScopes());
		assertThat(registration.getScopes()).isNotSameAs(updated.getScopes());
	}

	@Test
	public void buildWhenRegisteredClientProvidedThenEachPropertyMatches() {
		RegisteredClient registration = TestRegisteredClients.registeredClient().build();
		RegisteredClient updated = RegisteredClient.withRegisteredClient(registration).build();

		assertThat(registration.getId()).isEqualTo(updated.getId());
		assertThat(registration.getClientId()).isEqualTo(updated.getClientId());
		assertThat(registration.getClientSecret()).isEqualTo(updated.getClientSecret());
		assertThat(registration.getClientAuthenticationMethods()).isEqualTo(updated.getClientAuthenticationMethods());
		assertThat(registration.getAuthorizationGrantTypes()).isEqualTo(updated.getAuthorizationGrantTypes());
		assertThat(registration.getRedirectUris()).isEqualTo(updated.getRedirectUris());
		assertThat(registration.getScopes()).isEqualTo(updated.getScopes());
	}

	@Test
	public void buildWhenClientRegistrationValuesOverriddenThenPropagated() {
		RegisteredClient registration = TestRegisteredClients.registeredClient().build();
		String newSecret = "new-secret";
		String newScope = "new-scope";
		String newRedirectUri = "https://another-redirect-uri.com";
		RegisteredClient updated = RegisteredClient.withRegisteredClient(registration)
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

		assertThat(registration.getClientSecret()).isNotEqualTo(newSecret);
		assertThat(updated.getClientSecret()).isEqualTo(newSecret);
		assertThat(registration.getScopes()).doesNotContain(newScope);
		assertThat(updated.getScopes()).containsExactly(newScope);
		assertThat(registration.getRedirectUris()).doesNotContain(newRedirectUri);
		assertThat(updated.getRedirectUris()).containsExactly(newRedirectUri);
	}
}
