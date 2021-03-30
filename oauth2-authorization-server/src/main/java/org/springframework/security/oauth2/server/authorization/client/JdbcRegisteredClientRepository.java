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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.*;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * JDBC-backed registered client repository
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
public class JdbcRegisteredClientRepository implements RegisteredClientRepository {

	private static final Map<String, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_MAP;
	private static final Map<String, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_MAP;

	private static final String COLUMN_NAMES = "id, "
			+ "client_id, "
			+ "client_id_issued_at, "
			+ "client_secret, "
			+ "client_secret_expires_at, "
			+ "client_name, "
			+ "client_authentication_methods, "
			+ "authorization_grant_types, "
			+ "redirect_uris, "
			+ "scopes, "
			+ "client_settings,"
			+ "token_settings";

	private static final String TABLE_NAME = "oauth2_registered_client";

	private static final String LOAD_REGISTERED_CLIENT_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME + " WHERE ";

	private static final String INSERT_REGISTERED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME
			+ "(" + COLUMN_NAMES + ") values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	private RowMapper<RegisteredClient> registeredClientRowMapper;

	private Function<RegisteredClient, List<SqlParameterValue>> registeredClientParametersMapper;

	private final JdbcOperations jdbcOperations;

	private final LobHandler lobHandler = new DefaultLobHandler();

	private final ObjectMapper objectMapper;

	public JdbcRegisteredClientRepository(JdbcOperations jdbcOperations, ObjectMapper objectMapper) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(objectMapper, "objectMapper cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.objectMapper = objectMapper;
		this.registeredClientRowMapper = new DefaultRegisteredClientRowMapper();
		this.registeredClientParametersMapper = new DefaultRegisteredClientParametersMapper();
	}

	/**
	 * Allows changing of {@link RegisteredClient} row mapper implementation
	 *
	 * @param registeredClientRowMapper mapper implementation
	 */
	public void setRegisteredClientRowMapper(RowMapper<RegisteredClient> registeredClientRowMapper) {
		Assert.notNull(registeredClientRowMapper, "registeredClientRowMapper cannot be null");
		this.registeredClientRowMapper = registeredClientRowMapper;
	}

	/**
	 * Allows changing of SQL parameter mapper for {@link RegisteredClient}
	 *
	 * @param registeredClientParametersMapper mapper implementation
	 */
	public void setRegisteredClientParametersMapper(Function<RegisteredClient, List<SqlParameterValue>> registeredClientParametersMapper) {
		Assert.notNull(registeredClientParametersMapper, "registeredClientParameterMapper cannot be null");
		this.registeredClientParametersMapper = registeredClientParametersMapper;
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		RegisteredClient foundClient = this.findBy("id = ? OR client_id = ? OR client_secret = ?",
				registeredClient.getId(), registeredClient.getClientId(),
				registeredClient.getClientSecret().getBytes(StandardCharsets.UTF_8));

		if (null != foundClient) {
			Assert.isTrue(!foundClient.getId().equals(registeredClient.getId()),
					"Registered client must be unique. Found duplicate identifier: " + registeredClient.getId());
			Assert.isTrue(!foundClient.getClientId().equals(registeredClient.getClientId()),
					"Registered client must be unique. Found duplicate client identifier: " + registeredClient.getClientId());
			Assert.isTrue(!foundClient.getClientSecret().equals(registeredClient.getClientSecret()),
					"Registered client must be unique. Found duplicate client secret for identifier: " + registeredClient.getId());
		}

		List<SqlParameterValue> parameters = this.registeredClientParametersMapper.apply(registeredClient);

		try (LobCreator lobCreator = this.lobHandler.getLobCreator()) {
			PreparedStatementSetter pss = new LobCreatorArgumentPreparedStatementSetter(lobCreator, parameters.toArray());
			jdbcOperations.update(INSERT_REGISTERED_CLIENT_SQL, pss);
		}
	}

	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return findBy("id = ?", id);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		return findBy("client_id = ?", clientId);
	}

	private RegisteredClient findBy(String condStr, Object...args) {
		List<RegisteredClient> lst = jdbcOperations.query(
				LOAD_REGISTERED_CLIENT_SQL + condStr,
				registeredClientRowMapper, args);
		return !lst.isEmpty() ? lst.get(0) : null;
	}

	private class DefaultRegisteredClientRowMapper implements RowMapper<RegisteredClient> {

		private final LobHandler lobHandler = new DefaultLobHandler();

		private Collection<String> parseList(String s) {
			return s != null ? Arrays.asList(s.split("\\|")) : Collections.emptyList();
		}

		@Override
		@SuppressWarnings("unchecked")
		public RegisteredClient mapRow(ResultSet rs, int rowNum) throws SQLException {
			Collection<String> scopes = parseList(rs.getString("scopes"));
			List<AuthorizationGrantType> authGrantTypes = parseList(rs.getString("authorization_grant_types"))
					.stream().map(AUTHORIZATION_GRANT_TYPE_MAP::get).collect(Collectors.toList());
			List<ClientAuthenticationMethod> clientAuthMethods = parseList(rs.getString("client_authentication_methods"))
					.stream().map(CLIENT_AUTHENTICATION_METHOD_MAP::get).collect(Collectors.toList());
			Collection<String> redirectUris = parseList(rs.getString("redirect_uris"));
			Timestamp clientIssuedAt = rs.getTimestamp("client_id_issued_at");
			Timestamp clientSecretExpiresAt = rs.getTimestamp("client_secret_expires_at");
			byte[] clientSecretBytes = this.lobHandler.getBlobAsBytes(rs, "client_secret");
			String clientSecret = clientSecretBytes != null ? new String(clientSecretBytes, StandardCharsets.UTF_8) : null;
			RegisteredClient.Builder builder = RegisteredClient
					.withId(rs.getString("id"))
					.clientId(rs.getString("client_id"))
					.clientIdIssuedAt(clientIssuedAt != null ? clientIssuedAt.toInstant() : null)
					.clientSecret(clientSecret)
					.clientSecretExpiresAt(clientSecretExpiresAt != null ? clientSecretExpiresAt.toInstant() : null)
					.clientName(rs.getString("client_name"))
					.clientAuthenticationMethods(coll -> coll.addAll(clientAuthMethods))
					.authorizationGrantTypes(coll -> coll.addAll(authGrantTypes))
					.redirectUris(coll -> coll.addAll(redirectUris))
					.scopes(coll -> coll.addAll(scopes));

			RegisteredClient rc = builder.build();

			TokenSettings ts = rc.getTokenSettings();
			ClientSettings cs = rc.getClientSettings();

			try {
				String tokenSettingsJson = rs.getString("token_settings");
				if (tokenSettingsJson != null) {

					Map<String, Object> m = JdbcRegisteredClientRepository.this.objectMapper.readValue(tokenSettingsJson, Map.class);

					Number accessTokenTTL = (Number) m.get("access_token_ttl");
					if (accessTokenTTL != null) {
						ts.accessTokenTimeToLive(Duration.ofMillis(accessTokenTTL.longValue()));
					}

					Number refreshTokenTTL = (Number) m.get("refresh_token_ttl");
					if (refreshTokenTTL != null) {
						ts.refreshTokenTimeToLive(Duration.ofMillis(refreshTokenTTL.longValue()));
					}

					Boolean reuseRefreshTokens = (Boolean) m.get("reuse_refresh_tokens");
					if (reuseRefreshTokens != null) {
						ts.reuseRefreshTokens(reuseRefreshTokens);
					}
				}

				String clientSettingsJson = rs.getString("client_settings");
				if (clientSettingsJson != null) {

					Map<String, Object> m = JdbcRegisteredClientRepository.this.objectMapper.readValue(clientSettingsJson, Map.class);

					Boolean requireProofKey = (Boolean) m.get("require_proof_key");
					if (requireProofKey != null) {
						cs.requireProofKey(requireProofKey);
					}

					Boolean requireUserConsent = (Boolean) m.get("require_user_consent");
					if (requireUserConsent != null) {
						cs.requireUserConsent(requireUserConsent);
					}
				}


			} catch (JsonProcessingException e) {
				throw new IllegalArgumentException(e.getMessage(), e);
			}

			return rc;
		}
	}

	private class DefaultRegisteredClientParametersMapper implements Function<RegisteredClient, List<SqlParameterValue>> {
		@Override
		public List<SqlParameterValue> apply(RegisteredClient registeredClient) {
			try {
				List<String> clientAuthenticationMethodNames = new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
				for (ClientAuthenticationMethod clientAuthenticationMethod : registeredClient.getClientAuthenticationMethods()) {
					clientAuthenticationMethodNames.add(clientAuthenticationMethod.getValue());
				}

				List<String> authorizationGrantTypeNames = new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
				for (AuthorizationGrantType authorizationGrantType : registeredClient.getAuthorizationGrantTypes()) {
					authorizationGrantTypeNames.add(authorizationGrantType.getValue());
				}

				Instant issuedAt = registeredClient.getClientIdIssuedAt() != null ?
						registeredClient.getClientIdIssuedAt() : Instant.now();

				Timestamp clientSecretExpiresAt = registeredClient.getClientSecretExpiresAt() != null ?
						Timestamp.from(registeredClient.getClientSecretExpiresAt()) : null;

				Map<String, Object> clientSettings = new HashMap<>();
				clientSettings.put("require_proof_key", registeredClient.getClientSettings().requireProofKey());
				clientSettings.put("require_user_consent", registeredClient.getClientSettings().requireUserConsent());
				String clientSettingsJson = JdbcRegisteredClientRepository.this.objectMapper.writeValueAsString(clientSettings);

				Map<String, Object> tokenSettings = new HashMap<>();
				tokenSettings.put("access_token_ttl", registeredClient.getTokenSettings().accessTokenTimeToLive().toMillis());
				tokenSettings.put("reuse_refresh_tokens", registeredClient.getTokenSettings().reuseRefreshTokens());
				tokenSettings.put("refresh_token_ttl", registeredClient.getTokenSettings().refreshTokenTimeToLive().toMillis());
				String tokenSettingsJson = JdbcRegisteredClientRepository.this.objectMapper.writeValueAsString(tokenSettings);

				return Arrays.asList(
						new SqlParameterValue(Types.VARCHAR, registeredClient.getId()),
						new SqlParameterValue(Types.VARCHAR, registeredClient.getClientId()),
						new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(issuedAt)),
						new SqlParameterValue(Types.BLOB, registeredClient.getClientSecret().getBytes(StandardCharsets.UTF_8)),
						new SqlParameterValue(Types.TIMESTAMP, clientSecretExpiresAt),
						new SqlParameterValue(Types.VARCHAR, registeredClient.getClientName()),
						new SqlParameterValue(Types.VARCHAR, String.join("|", clientAuthenticationMethodNames)),
						new SqlParameterValue(Types.VARCHAR, String.join("|", authorizationGrantTypeNames)),
						new SqlParameterValue(Types.VARCHAR, String.join("|", registeredClient.getRedirectUris())),
						new SqlParameterValue(Types.VARCHAR, String.join("|", registeredClient.getScopes())),
						new SqlParameterValue(Types.VARCHAR, clientSettingsJson),
						new SqlParameterValue(Types.VARCHAR, tokenSettingsJson));
			} catch (JsonProcessingException e) {
				throw new IllegalArgumentException(e.getMessage(), e);
			}
		}
	}

	private static final class LobCreatorArgumentPreparedStatementSetter extends ArgumentPreparedStatementSetter {

		protected final LobCreator lobCreator;

		private LobCreatorArgumentPreparedStatementSetter(LobCreator lobCreator, Object[] args) {
			super(args);
			this.lobCreator = lobCreator;
		}

		@Override
		protected void doSetValue(PreparedStatement ps, int parameterPosition, Object argValue) throws SQLException {
			if (argValue instanceof SqlParameterValue) {
				SqlParameterValue paramValue = (SqlParameterValue) argValue;
				if (paramValue.getSqlType() == Types.BLOB) {
					if (paramValue.getValue() != null) {
						Assert.isInstanceOf(byte[].class, paramValue.getValue(),
								"Value of blob parameter must be byte[]");
					}
					byte[] valueBytes = (byte[]) paramValue.getValue();
					this.lobCreator.setBlobAsBytes(ps, parameterPosition, valueBytes);
					return;
				}
			}
			super.doSetValue(ps, parameterPosition, argValue);
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
