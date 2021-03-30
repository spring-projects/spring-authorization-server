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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StreamUtils;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

/**
 * JDBC-backed registered client repository tests
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
public class JdbcRegisteredClientRepositoryTests {

	private final String SCRIPT = "/org/springframework/security/oauth2/server/authorization/client/oauth2_registered_client.sql";

	private DriverManagerDataSource dataSource;

	private JdbcRegisteredClientRepository clients;

	private RegisteredClient registration;

	private JdbcTemplate jdbc;

	@Before
	public void setup() throws Exception {
		this.dataSource = new DriverManagerDataSource();
		this.dataSource.setDriverClassName("org.hsqldb.jdbcDriver");
		this.dataSource.setUrl("jdbc:hsqldb:mem:oauthtest");
		this.dataSource.setUsername("sa");
		this.dataSource.setPassword("");

		this.jdbc = new JdbcTemplate(this.dataSource);

		// execute scripts
		try (InputStream is = JdbcRegisteredClientRepositoryTests.class.getResourceAsStream(SCRIPT)) {
			assertThat(is).isNotNull().describedAs("Cannot open resource file: " + SCRIPT);
			String ddls = StreamUtils.copyToString(is, Charset.defaultCharset());
			for (String ddl : ddls.split(";\n")) {
				if (!ddl.trim().isEmpty()) {
					this.jdbc.execute(ddl.trim());
				}
			}
		}

		this.clients = new JdbcRegisteredClientRepository(this.jdbc, new ObjectMapper());
		this.registration = TestRegisteredClients.registeredClient().build();

		this.clients.save(this.registration);
	}

	@After
	public void destroyDatabase() {
		this.jdbc.update("truncate table oauth2_registered_client");
		new JdbcTemplate(this.dataSource).execute("SHUTDOWN");
	}

	@Test
	public void whenJdbcOperationsNullThenThrow() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcRegisteredClientRepository(null, new ObjectMapper()))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	public void whenObjectMapperNullThenThrow() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcRegisteredClientRepository(this.jdbc, null))
				.withMessage("objectMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void whenSetNullRegisteredClientRowMapperThenThrow() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.setRegisteredClientRowMapper(null))
				.withMessage("registeredClientRowMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void whenSetNullRegisteredClientParameterMapperThenThrow() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.setRegisteredClientParametersMapper(null))
				.withMessage("registeredClientParameterMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void findByIdWhenFoundThenFound() {
		String id = this.registration.getId();
		assertRegisteredClientIsEqualTo(this.clients.findById(id), this.registration);
	}

	@Test
	public void findByIdWhenNotFoundThenNull() {
		RegisteredClient client = this.clients.findById("noooope");
		assertThat(client).isNull();
	}

	@Test
	public void findByIdWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.findById(null))
				.withMessage("id cannot be empty");
		// @formatter:on
	}

	@Test
	public void findByClientIdWhenFoundThenFound() {
		String id = this.registration.getClientId();
		assertRegisteredClientIsEqualTo(this.clients.findByClientId(id), this.registration);
	}

	@Test
	public void findByClientIdWhenNotFoundThenNull() {
		RegisteredClient client = this.clients.findByClientId("noooope");
		assertThat(client).isNull();
	}

	@Test
	public void findByClientIdWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.findByClientId(null))
				.withMessage("clientId cannot be empty");
		// @formatter:on
	}

	@Test
	public void saveWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.save(null))
				.withMessageContaining("registeredClient cannot be null");
	}

	@Test
	public void saveWhenExistingIdThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient = createRegisteredClient(
				this.registration.getId(), "client-id-2", "client-secret-2");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.save(registeredClient))
				.withMessage("Registered client must be unique. Found duplicate identifier: " + registeredClient.getId());
	}

	@Test
	public void saveWhenExistingClientIdThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient = createRegisteredClient(
				"client-2", this.registration.getClientId(), "client-secret-2");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.save(registeredClient))
				.withMessage("Registered client must be unique. Found duplicate client identifier: " + registeredClient.getClientId());
	}

	@Test
	public void saveWhenExistingClientSecretThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient = createRegisteredClient(
				"client-2", "client-id-2", this.registration.getClientSecret());
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.clients.save(registeredClient))
				.withMessage("Registered client must be unique. Found duplicate client secret for identifier: " + registeredClient.getId());
	}

	@Test
	public void saveWhenSavedAndFindByIdThenFound() {
		RegisteredClient registeredClient = createRegisteredClient();
		this.clients.save(registeredClient);
		RegisteredClient savedClient = this.clients.findById(registeredClient.getId());
		assertRegisteredClientIsEqualTo(savedClient, registeredClient);
	}

	@Test
	public void saveWhenSavedAndFindByClientIdThenFound() {
		RegisteredClient registeredClient = createRegisteredClient();
		this.clients.save(registeredClient);
		RegisteredClient savedClient = this.clients.findByClientId(registeredClient.getClientId());
		assertRegisteredClientIsEqualTo(savedClient, registeredClient);
	}

	@Test
	public void whenSaveRegistrationWithAllAttrsThenSaved() {
		Instant issuedAt = Instant.now(), expiresAt = issuedAt.plus(Duration.ofDays(30));
		RegisteredClient client = TestRegisteredClients.registeredClient2()
				.clientIdIssuedAt(issuedAt)
				.clientSecretExpiresAt(expiresAt)
				.clientSecret("secret2")
				.clientName("some_client_name")
				.redirectUri("https://example2.com")
				.clientSettings(cs -> {
					cs.requireProofKey(true);
					cs.requireUserConsent(true);
				})
				.tokenSettings(ts -> {
					ts.accessTokenTimeToLive(Duration.ofMinutes(3));
					ts.reuseRefreshTokens(true);
					ts.refreshTokenTimeToLive(Duration.ofMinutes(300));
				})
				.build();

		this.clients.save(client);

		RegisteredClient retrievedClient = this.clients.findById(client.getId());

		assertRegisteredClientIsEqualTo(retrievedClient, client);
	}

	private void assertRegisteredClientIsEqualTo(RegisteredClient rc, RegisteredClient ref) {
		assertThat(rc).isNotNull();
		assertThat(rc.getId()).isEqualTo(ref.getId());
		assertThat(rc.getClientId()).isEqualTo(ref.getClientId());

		if (ref.getClientIdIssuedAt() != null) {
			// This can be set to default value
			Instant inst = ref.getClientIdIssuedAt();
			assertThat(rc.getClientIdIssuedAt()).isBetween(inst.minusMillis(1), inst.plusMillis(1));
		}

		assertThat(rc.getClientSecret()).isEqualTo(ref.getClientSecret());

		if (ref.getClientSecretExpiresAt() != null) {
			Instant inst = ref.getClientSecretExpiresAt();
			assertThat(rc.getClientSecretExpiresAt()).isBetween(inst.minusMillis(1), inst.plusMillis(1));
		} else {
			assertThat(rc.getClientSecretExpiresAt()).isNull();
		}

		assertThat(rc.getClientName()).isEqualTo(ref.getClientName());
		assertThat(rc.getClientAuthenticationMethods()).isEqualTo(ref.getClientAuthenticationMethods());
		assertThat(rc.getAuthorizationGrantTypes()).isEqualTo(ref.getAuthorizationGrantTypes());
		assertThat(rc.getRedirectUris()).isEqualTo(ref.getRedirectUris());
		assertThat(rc.getScopes()).isEqualTo(ref.getScopes());
		assertThat(rc.getClientSettings().requireUserConsent()).isEqualTo(ref.getClientSettings().requireUserConsent());
		assertThat(rc.getClientSettings().requireProofKey()).isEqualTo(ref.getClientSettings().requireProofKey());
		assertThat(rc.getTokenSettings().reuseRefreshTokens()).isEqualTo(ref.getTokenSettings().reuseRefreshTokens());
		assertThat(rc.getTokenSettings().accessTokenTimeToLive()).isEqualTo(ref.getTokenSettings().accessTokenTimeToLive());
		assertThat(rc.getTokenSettings().refreshTokenTimeToLive()).isEqualTo(ref.getTokenSettings().refreshTokenTimeToLive());
	}

	private static RegisteredClient createRegisteredClient() {
		return createRegisteredClient("client-2", "client-id-2", "client-secret-2");
	}


	private static RegisteredClient createRegisteredClient(String id, String clientId, String clientSecret) {
		// @formatter:off
		return RegisteredClient.withId(id)
				.clientId(clientId)
				.clientSecret(clientSecret)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.redirectUri("https://client.example.com")
				.scope("scope1")
				.build();
		// @formatter:on
	}

}
