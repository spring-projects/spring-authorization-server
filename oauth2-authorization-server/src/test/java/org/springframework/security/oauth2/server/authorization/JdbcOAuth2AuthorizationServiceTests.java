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
package org.springframework.security.oauth2.server.authorization;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Function;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link JdbcOAuth2AuthorizationService}.
 *
 * @author Ovidiu Popa
 */
public class JdbcOAuth2AuthorizationServiceTests {
	private static final String OAUTH2_AUTHORIZATION_SCHEMA_SQL_RESOURCE = "org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql";
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
	private static final String ID = "id";
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final String PRINCIPAL_NAME = "principal";
	private static final AuthorizationGrantType AUTHORIZATION_GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;
	private static final OAuth2AuthorizationCode AUTHORIZATION_CODE = new OAuth2AuthorizationCode(
			"code", Instant.now().truncatedTo(ChronoUnit.MILLIS), Instant.now().plus(5, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS));

	private EmbeddedDatabase db;
	private JdbcOperations jdbcOperations;
	private RegisteredClientRepository registeredClientRepository;
	private JdbcOAuth2AuthorizationService authorizationService;

	@Before
	public void setUp() {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = new JdbcOAuth2AuthorizationService(this.jdbcOperations, this.registeredClientRepository);
	}

	@After
	public void tearDown() {
		this.db.shutdown();
	}

	@Test
	public void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new JdbcOAuth2AuthorizationService(null, this.registeredClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new JdbcOAuth2AuthorizationService(this.jdbcOperations, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenLobHandlerIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new JdbcOAuth2AuthorizationService(this.jdbcOperations, this.registeredClientRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("lobHandler cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationRowMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationService.setAuthorizationRowMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationRowMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationParametersMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationService.setAuthorizationParametersMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationParametersMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void saveWhenAuthorizationNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationService.save(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization cannot be null");
		// @formatter:on
	}

	@Test
	public void saveWhenAuthorizationNewThenSaved() {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.token(AUTHORIZATION_CODE)
				.build();
		this.authorizationService.save(expectedAuthorization);

		OAuth2Authorization authorization = this.authorizationService.findById(ID);
		assertThat(authorization).isEqualTo(expectedAuthorization);
	}

	@Test
	public void saveWhenAuthorizationExistsThenUpdated() {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		OAuth2Authorization originalAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.token(AUTHORIZATION_CODE)
				.build();
		this.authorizationService.save(originalAuthorization);

		OAuth2Authorization authorization = this.authorizationService.findById(
				originalAuthorization.getId());
		assertThat(authorization).isEqualTo(originalAuthorization);

		OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
				.attribute("custom-name-1", "custom-value-1")
				.build();
		this.authorizationService.save(updatedAuthorization);

		authorization = this.authorizationService.findById(
				updatedAuthorization.getId());
		assertThat(authorization).isEqualTo(updatedAuthorization);
		assertThat(authorization).isNotEqualTo(originalAuthorization);
	}

	@Test
	public void saveLoadAuthorizationWhenCustomStrategiesSetThenCalled() throws Exception {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		OAuth2Authorization originalAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.token(AUTHORIZATION_CODE)
				.build();
		ObjectMapper objectMapper = new ObjectMapper();
		RowMapper<OAuth2Authorization> authorizationRowMapper = spy(
				new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(
						this.registeredClientRepository));
		this.authorizationService.setAuthorizationRowMapper(authorizationRowMapper);
		Function<OAuth2Authorization, List<SqlParameterValue>> authorizationParametersMapper = spy(
				new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper());
		this.authorizationService.setAuthorizationParametersMapper(authorizationParametersMapper);

		this.authorizationService.save(originalAuthorization);
		OAuth2Authorization authorization = this.authorizationService.findById(
				originalAuthorization.getId());
		assertThat(authorization).isEqualTo(originalAuthorization);
		verify(authorizationRowMapper).mapRow(any(), anyInt());
		verify(authorizationParametersMapper).apply(any());
	}

	@Test
	public void removeWhenAuthorizationNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationService.remove(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization cannot be null");
		// @formatter:on
	}

	@Test
	public void removeWhenAuthorizationProvidedThenRemoved() {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.token(AUTHORIZATION_CODE)
				.build();

		this.authorizationService.save(expectedAuthorization);
		OAuth2Authorization authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE.getTokenValue(), AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(expectedAuthorization);

		this.authorizationService.remove(expectedAuthorization);
		authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE.getTokenValue(), AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isNull();
	}

	@Test
	public void findByIdWhenIdNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationService.findById(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("id cannot be empty");
		// @formatter:on
	}

	@Test
	public void findByIdWhenIdEmptyThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationService.findById(" "))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("id cannot be empty");
		// @formatter:on
	}

	@Test
	public void findByTokenWhenTokenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationService.findByToken(null, AUTHORIZATION_CODE_TOKEN_TYPE))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be empty");
		// @formatter:on
	}

	@Test
	public void findByTokenWhenStateExistsThenFound() {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		String state = "state";
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.attribute(OAuth2ParameterNames.STATE, state)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				state, STATE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(state, null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenAuthorizationCodeExistsThenFound() {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.token(AUTHORIZATION_CODE)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				AUTHORIZATION_CODE.getTokenValue(), AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(AUTHORIZATION_CODE.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenAccessTokenExistsThenFound() {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token", Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.MILLIS), Instant.now().truncatedTo(ChronoUnit.MILLIS));
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.token(AUTHORIZATION_CODE)
				.accessToken(accessToken)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				accessToken.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(accessToken.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenRefreshTokenExistsThenFound() {
		when(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken2("refresh-token",
				Instant.now().truncatedTo(ChronoUnit.MILLIS),
				Instant.now().plus(5, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS));
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.refreshToken(refreshToken)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				refreshToken.getTokenValue(), OAuth2TokenType.REFRESH_TOKEN);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(refreshToken.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenWrongTokenTypeThenNotFound() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now().truncatedTo(ChronoUnit.MILLIS));
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.refreshToken(refreshToken)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				refreshToken.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
		assertThat(result).isNull();
	}

	@Test
	public void findByTokenWhenTokenDoesNotExistThenNull() {
		OAuth2Authorization result = this.authorizationService.findByToken(
				"access-token", OAuth2TokenType.ACCESS_TOKEN);
		assertThat(result).isNull();
	}

	private static EmbeddedDatabase createDb() {
		return createDb(OAUTH2_AUTHORIZATION_SCHEMA_SQL_RESOURCE);
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
}
