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

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * A {@link RegisteredClientRepository} that stores {@link RegisteredClient}(s) in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation is recommended ONLY to be used during development/testing.
 *
 * @author Anoop Garlapati
 * @see RegisteredClientRepository
 * @see RegisteredClient
 * @since 0.0.1
 */
public final class InMemoryRegisteredClientRepository implements RegisteredClientRepository {
	private final Map<String, RegisteredClient> idRegistrationMap;
	private final Map<String, RegisteredClient> clientIdRegistrationMap;

	/**
	 * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryRegisteredClientRepository(RegisteredClient... registrations) {
		this(Arrays.asList(registrations));
	}

	/**
	 * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryRegisteredClientRepository(List<RegisteredClient> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		ConcurrentHashMap<String, RegisteredClient> idRegistrationMapResult = new ConcurrentHashMap<>();
		ConcurrentHashMap<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
		for (RegisteredClient registration : registrations) {
			Assert.notNull(registration, "registration cannot be null");
			String id = registration.getId();
			if (idRegistrationMapResult.containsKey(id)) {
				throw new IllegalArgumentException("Registered client must be unique. " +
						"Found duplicate identifier: " + id);
			}
			String clientId = registration.getClientId();
			if (clientIdRegistrationMapResult.containsKey(clientId)) {
				throw new IllegalArgumentException("Registered client must be unique. " +
						"Found duplicate client identifier: " + clientId);
			}
			idRegistrationMapResult.put(id, registration);
			clientIdRegistrationMapResult.put(clientId, registration);
		}
		this.idRegistrationMap = idRegistrationMapResult;
		this.clientIdRegistrationMap = clientIdRegistrationMapResult;
	}

	@Nullable
	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.idRegistrationMap.get(id);
	}

	@Nullable
	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		return this.clientIdRegistrationMap.get(clientId);
	}
}
