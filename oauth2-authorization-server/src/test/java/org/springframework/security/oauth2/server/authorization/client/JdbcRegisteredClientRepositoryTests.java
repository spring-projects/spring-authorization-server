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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * JDBC-backed registered client repository tests
 *
 * @author Rafal Lewczuk
 * @author Steve Riesenberg
 * @since 0.1.2
 */
public class JdbcRegisteredClientRepositoryTests {

	private static final String REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE = "/org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql";
	private static final String CUSTOM_REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE = "/org/springframework/security/oauth2/server/authorization/client/custom-oauth2-registered-client-schema.sql";

	private DriverManagerDataSource dataSource;

	private JdbcRegisteredClientRepository registeredClientRepository;

	private RegisteredClient registeredClient;

	private EmbeddedDatabase db;

	private JdbcOperations jdbcOperations;

	@Before
	public void setup() throws Exception {
		this.db = createDb(REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE);
		this.jdbcOperations = new JdbcTemplate(this.db);

		this.registeredClientRepository = new JdbcRegisteredClientRepository(this.jdbcOperations);
		this.registeredClient = TestRegisteredClients.registeredClient().build();

		this.registeredClientRepository.save(this.registeredClient);
	}

	@After
	public void destroyDatabase() {
		this.db.shutdown();
	}

	@Test
	public void whenJdbcOperationsNullThenThrow() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcRegisteredClientRepository(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	public void whenSetNullRegisteredClientRowMapperThenThrow() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.setRegisteredClientRowMapper(null))
				.withMessage("registeredClientRowMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void whenSetNullRegisteredClientParameterMapperThenThrow() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.setRegisteredClientParametersMapper(null))
				.withMessage("registeredClientParameterMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void findByIdWhenFoundThenFound() {
		String id = this.registeredClient.getId();
		assertRegisteredClientIsEqualTo(this.registeredClientRepository.findById(id), this.registeredClient);
	}

	@Test
	public void findByIdWhenNotFoundThenNull() {
		RegisteredClient client = this.registeredClientRepository.findById("noooope");
		assertThat(client).isNull();
	}

	@Test
	public void findByIdWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.findById(null))
				.withMessage("id cannot be empty");
		// @formatter:on
	}

	@Test
	public void findByClientIdWhenFoundThenFound() {
		String id = this.registeredClient.getClientId();
		assertRegisteredClientIsEqualTo(this.registeredClientRepository.findByClientId(id), this.registeredClient);
	}

	@Test
	public void findByClientIdWhenNotFoundThenNull() {
		RegisteredClient client = this.registeredClientRepository.findByClientId("noooope");
		assertThat(client).isNull();
	}

	@Test
	public void findByClientIdWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.findByClientId(null))
				.withMessage("clientId cannot be empty");
		// @formatter:on
	}

	@Test
	public void saveWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.save(null))
				.withMessageContaining("registeredClient cannot be null");
	}

	@Test
	public void saveWhenExistingIdThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient = createRegisteredClient(
				this.registeredClient.getId(), "client-id-2", "client-secret-2");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.save(registeredClient))
				.withMessage("Registered client must be unique. Found duplicate identifier: " + registeredClient.getId());
	}

	@Test
	public void saveWhenExistingClientIdThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient = createRegisteredClient(
				"client-2", this.registeredClient.getClientId(), "client-secret-2");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.save(registeredClient))
				.withMessage("Registered client must be unique. Found duplicate client identifier: " + registeredClient.getClientId());
	}

	@Test
	public void saveWhenExistingClientSecretThenSuccess() {
		RegisteredClient registeredClient = createRegisteredClient(
				"client-2", "client-id-2", this.registeredClient.getClientSecret());
		this.registeredClientRepository.save(registeredClient);
		RegisteredClient savedClient = this.registeredClientRepository.findById(registeredClient.getId());
		assertRegisteredClientIsEqualTo(savedClient, registeredClient);
	}

	@Test
	public void saveWhenSavedAndFindByIdThenFound() {
		RegisteredClient registeredClient = createRegisteredClient();
		this.registeredClientRepository.save(registeredClient);
		RegisteredClient savedClient = this.registeredClientRepository.findById(registeredClient.getId());
		assertRegisteredClientIsEqualTo(savedClient, registeredClient);
	}

	@Test
	public void saveWhenSavedAndFindByClientIdThenFound() {
		RegisteredClient registeredClient = createRegisteredClient();
		this.registeredClientRepository.save(registeredClient);
		RegisteredClient savedClient = this.registeredClientRepository.findByClientId(registeredClient.getClientId());
		assertRegisteredClientIsEqualTo(savedClient, registeredClient);
	}

	@Test
	public void saveWhenPublicClientSavedAndFindByClientIdThenFound() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		this.registeredClientRepository.save(registeredClient);
		RegisteredClient savedClient = this.registeredClientRepository.findByClientId(registeredClient.getClientId());
		assertRegisteredClientIsEqualTo(savedClient, registeredClient);
	}

	@Test
	public void saveWhenMultiplePublicClientsSavedAndFindByIdThenFound() {
		RegisteredClient registeredClient1 = TestRegisteredClients.registeredPublicClient()
				.id("1").clientId("a").build();
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredPublicClient()
				.id("2").clientId("b").build();
		this.registeredClientRepository.save(registeredClient1);
		this.registeredClientRepository.save(registeredClient2);
		RegisteredClient savedClient = this.registeredClientRepository.findByClientId(registeredClient2.getClientId());
		assertRegisteredClientIsEqualTo(savedClient, registeredClient2);
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

		this.registeredClientRepository.save(client);

		RegisteredClient retrievedClient = this.registeredClientRepository.findById(client.getId());

		assertRegisteredClientIsEqualTo(retrievedClient, client);
	}

	@Test
	public void tableDefinitionWhenCustomThenAbleToOverride() {
		EmbeddedDatabase db = createDb(CUSTOM_REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE);
		CustomJdbcRegisteredClientRepository registeredClientRepository =
				new CustomJdbcRegisteredClientRepository(new JdbcTemplate(db));
		registeredClientRepository.save(this.registeredClient);
		RegisteredClient foundClient1 = registeredClientRepository.findById(this.registeredClient.getId());
		assertThat(foundClient1).isNotNull();
		assertRegisteredClientIsEqualTo(foundClient1, this.registeredClient);
		RegisteredClient foundClient2 = registeredClientRepository.findByClientId(this.registeredClient.getClientId());
		assertThat(foundClient2).isNotNull();
		assertRegisteredClientIsEqualTo(foundClient2, this.registeredClient);
		db.shutdown();
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

	private static EmbeddedDatabase createDb(String schema) {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(schema)
				.build();
		// @formatter:on
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

	private static final class CustomJdbcRegisteredClientRepository extends JdbcRegisteredClientRepository {

		private static final String COLUMN_NAMES = "id, "
				+ "clientId, "
				+ "clientIdIssuedAt, "
				+ "clientSecret, "
				+ "clientSecretExpiresAt, "
				+ "clientName, "
				+ "clientAuthenticationMethods, "
				+ "authorizationGrantTypes, "
				+ "redirectUris, "
				+ "scopes, "
				+ "clientSettings,"
				+ "tokenSettings";

		private static final String TABLE_NAME = "oauth2RegisteredClient";

		private static final String LOAD_REGISTERED_CLIENT_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME + " WHERE ";

		private static final String INSERT_REGISTERED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME
				+ " (" + COLUMN_NAMES + ") values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

		CustomJdbcRegisteredClientRepository(JdbcOperations jdbcOperations) {
			super(jdbcOperations);
			setRegisteredClientRowMapper(new CustomRegisteredClientRowMapper());
		}

		@Override
		public void save(RegisteredClient registeredClient) {
			List<SqlParameterValue> parameters = getRegisteredClientParametersMapper().apply(registeredClient);
			PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
			getJdbcOperations().update(INSERT_REGISTERED_CLIENT_SQL, pss);
		}

		@Override
		public RegisteredClient findById(String id) {
			return findBy("id = ?", id);
		}

		@Override
		public RegisteredClient findByClientId(String clientId) {
			return findBy("clientId = ?", clientId);
		}

		private RegisteredClient findBy(String filter, Object... args) {
			List<RegisteredClient> result = getJdbcOperations()
					.query(LOAD_REGISTERED_CLIENT_SQL + filter, getRegisteredClientRowMapper(), args);
			return !result.isEmpty() ? result.get(0) : null;
		}

		private static final class CustomRegisteredClientRowMapper implements RowMapper<RegisteredClient> {

			private static final Map<String, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_MAP;
			private static final Map<String, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_MAP;

			private final ObjectMapper objectMapper = new ObjectMapper();

			@Override
			public RegisteredClient mapRow(ResultSet rs, int rowNum) throws SQLException {
				Set<String> clientScopes = StringUtils.commaDelimitedListToSet(rs.getString("scopes"));
				Set<String> authGrantTypes = StringUtils.commaDelimitedListToSet(rs.getString("authorizationGrantTypes"));
				Set<String> clientAuthMethods = StringUtils.commaDelimitedListToSet(rs.getString("clientAuthenticationMethods"));
				Set<String> redirectUris = StringUtils.commaDelimitedListToSet(rs.getString("redirectUris"));
				Timestamp clientIssuedAt = rs.getTimestamp("clientIdIssuedAt");
				Timestamp clientSecretExpiresAt = rs.getTimestamp("clientSecretExpiresAt");
				String clientSecret = rs.getString("clientSecret");
				RegisteredClient.Builder builder = RegisteredClient
						.withId(rs.getString("id"))
						.clientId(rs.getString("clientId"))
						.clientIdIssuedAt(clientIssuedAt != null ? clientIssuedAt.toInstant() : null)
						.clientSecret(clientSecret)
						.clientSecretExpiresAt(clientSecretExpiresAt != null ? clientSecretExpiresAt.toInstant() : null)
						.clientName(rs.getString("clientName"))
						.authorizationGrantTypes((grantTypes) -> authGrantTypes.forEach(authGrantType ->
								grantTypes.add(AUTHORIZATION_GRANT_TYPE_MAP.get(authGrantType))))
						.clientAuthenticationMethods((authenticationMethods) -> clientAuthMethods.forEach(clientAuthMethod ->
								authenticationMethods.add(CLIENT_AUTHENTICATION_METHOD_MAP.get(clientAuthMethod))))
						.redirectUris((uris) -> uris.addAll(redirectUris))
						.scopes((scopes) -> scopes.addAll(clientScopes));

				RegisteredClient registeredClient = builder.build();
				registeredClient.getClientSettings().settings().putAll(parseMap(rs.getString("clientSettings")));
				registeredClient.getTokenSettings().settings().putAll(parseMap(rs.getString("tokenSettings")));

				return registeredClient;
			}

			private Map<String, Object> parseMap(String data) {
				try {
					return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
				} catch (Exception ex) {
					throw new IllegalArgumentException(ex.getMessage(), ex);
				}
			}

			static {
				Map<String, AuthorizationGrantType> am = new HashMap<>();
				for (AuthorizationGrantType a : Arrays.asList(
						AuthorizationGrantType.AUTHORIZATION_CODE,
						AuthorizationGrantType.REFRESH_TOKEN,
						AuthorizationGrantType.CLIENT_CREDENTIALS,
						AuthorizationGrantType.PASSWORD,
						AuthorizationGrantType.IMPLICIT)) {
					am.put(a.getValue(), a);
				}
				AUTHORIZATION_GRANT_TYPE_MAP = Collections.unmodifiableMap(am);

				Map<String, ClientAuthenticationMethod> cm = new HashMap<>();
				for (ClientAuthenticationMethod c : Arrays.asList(
						ClientAuthenticationMethod.NONE,
						ClientAuthenticationMethod.BASIC,
						ClientAuthenticationMethod.POST)) {
					cm.put(c.getValue(), c);
				}
				CLIENT_AUTHENTICATION_METHOD_MAP = Collections.unmodifiableMap(cm);
			}

		}

	}

}
