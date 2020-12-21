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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link InMemoryRegisteredClientRepository}.
 *
 * @author Anoop Garlapati
 */
public class InMemoryRegisteredClientRepositoryTests {
	private RegisteredClient registration = TestRegisteredClients.registeredClient().build();

	private InMemoryRegisteredClientRepository clients = new InMemoryRegisteredClientRepository(this.registration);

	@Test
	public void constructorVarargsRegisteredClientWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient registration = null;
			new InMemoryRegisteredClientRepository(registration);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorListRegisteredClientWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			List<RegisteredClient> registrations = null;
			new InMemoryRegisteredClientRepository(registrations);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorListRegisteredClientWhenEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			List<RegisteredClient> registrations = Collections.emptyList();
			new InMemoryRegisteredClientRepository(registrations);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorListRegisteredClientWhenDuplicateIdThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient anotherRegistrationWithSameId = TestRegisteredClients.registeredClient2()
					.id(this.registration.getId()).build();
			List<RegisteredClient> registrations = Arrays.asList(this.registration, anotherRegistrationWithSameId);
			new InMemoryRegisteredClientRepository(registrations);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorListRegisteredClientWhenDuplicateClientIdThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient anotherRegistrationWithSameClientId = TestRegisteredClients.registeredClient2()
					.clientId(this.registration.getClientId()).build();
			List<RegisteredClient> registrations = Arrays.asList(this.registration,
					anotherRegistrationWithSameClientId);
			new InMemoryRegisteredClientRepository(registrations);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void findByIdWhenFoundThenFound() {
		String id = this.registration.getId();
		assertThat(this.clients.findById(id)).isEqualTo(this.registration);
	}

	@Test
	public void findByIdWhenNotFoundThenNull() {
		String missingId = this.registration.getId() + "MISSING";
		assertThat(this.clients.findById(missingId)).isNull();
	}

	@Test
	public void findByIdWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.clients.findById(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void findByClientIdWhenFoundThenFound() {
		String clientId = this.registration.getClientId();
		assertThat(this.clients.findByClientId(clientId)).isEqualTo(this.registration);
	}

	@Test
	public void findByClientIdWhenNotFoundThenNull() {
		String missingClientId = this.registration.getClientId() + "MISSING";
		assertThat(this.clients.findByClientId(missingClientId)).isNull();
	}

	@Test
	public void findByClientIdWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.clients.findByClientId(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveNullRegisteredClientThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.clients.saveClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("registeredClient cannot be null");
	}

	@Test
	public void saveRegisteredClientThenReturnsSavedRegisteredClientWhenSearchedById() {
		RegisteredClient registeredClient = RegisteredClient.withId("new-client")
				.clientId("new-client")
				.clientSecret("secret")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("https://newclient.com")
				.scope("scope1").build();

		this.clients.saveClient(registeredClient);

		RegisteredClient savedClient = this.clients.findById("new-client");

		assertThat(savedClient).isNotNull().isEqualTo(registeredClient);
	}

	@Test
	public void saveRegisteredClientThenReturnsSavedRegisteredClientWhenSearchedByClientId() {
		RegisteredClient registeredClient = RegisteredClient.withId("id1")
				.clientId("new-client-id")
				.clientSecret("secret")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("https://newclient.com")
				.scope("scope1").build();

		this.clients.saveClient(registeredClient);

		RegisteredClient savedClient = this.clients.findByClientId("new-client-id");

		assertThat(savedClient).isNotNull().isEqualTo(registeredClient);
	}

	@Test
	public void saveRegisteredClientWithExistingIdThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient registeredClient = RegisteredClient.withId("registration-1")
					.clientId("new-client")
					.clientSecret("secret")
					.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
					.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
					.redirectUri("https://newclient.com")
					.scope("scope1").build();

			this.clients.saveClient(registeredClient);
		}).isInstanceOf(IllegalArgumentException.class)
		.hasMessageContaining("Registered client must be unique. Found duplicate identifier");
	}

	@Test
	public void saveRegisteredClientWithExistingClientIdThrowIllegalArgumentException() {
		assertThatThrownBy(() -> {
			RegisteredClient registeredClient = RegisteredClient.withId("new-client")
					.clientId("client-1")
					.clientSecret("secret")
					.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
					.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
					.redirectUri("https://newclient.com")
					.scope("scope1").build();

			this.clients.saveClient(registeredClient);
		}).isInstanceOf(IllegalArgumentException.class)
		.hasMessageContaining("Registered client must be unique. Found duplicate client identifier");
	}
}
