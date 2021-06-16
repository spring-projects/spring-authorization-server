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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link JdbcOAuth2AuthorizationConsentService}.
 *
 * @author Ovidiu Popa
 */
public class JdbcOAuth2AuthorizationConsentServiceTests {

	private static final String OAUTH2_AUTHORIZATION_CONSENT_SCHEMA_SQL_RESOURCE = "org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql";
	private static final String PRINCIPAL_NAME = "principal-name";
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();

	private static final OAuth2AuthorizationConsent AUTHORIZATION_CONSENT =
			OAuth2AuthorizationConsent.withId(REGISTERED_CLIENT.getId(), PRINCIPAL_NAME)
					.authority(new SimpleGrantedAuthority("some.authority"))
					.build();

	private EmbeddedDatabase db;
	private JdbcOperations jdbcOperations;
	private RegisteredClientRepository registeredClientRepository;
	private JdbcOAuth2AuthorizationConsentService authorizationConsentService;

	@Test
	public void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new JdbcOAuth2AuthorizationConsentService(null, this.registeredClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new JdbcOAuth2AuthorizationConsentService(this.jdbcOperations, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationConsentRowMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationConsentService.setAuthorizationConsentRowMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationConsentRowMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationConsentParametersMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationConsentService.setAuthorizationConsentParametersMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationConsentParametersMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void saveWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizationConsentService.save(null))
				.withMessage("authorizationConsent cannot be null");
		// @formatter:on
	}

	@Test
	public void saveWhenAuthorizationConsentNewThenSaved() {
		OAuth2AuthorizationConsent expectedAuthorizationConsent =
				OAuth2AuthorizationConsent.withId("new-client", "new-principal")
						.authority(new SimpleGrantedAuthority("new.authority"))
						.build();

		RegisteredClient newRegisteredClient = TestRegisteredClients.registeredClient()
				.id("new-client").build();

		when(registeredClientRepository.findById(eq(newRegisteredClient.getId())))
				.thenReturn(newRegisteredClient);

		this.authorizationConsentService.save(expectedAuthorizationConsent);

		OAuth2AuthorizationConsent authorizationConsent =
				this.authorizationConsentService.findById("new-client", "new-principal");
		assertThat(authorizationConsent).isEqualTo(expectedAuthorizationConsent);
	}

	@Test
	public void saveWhenAuthorizationConsentExistsThenUpdated() {
		OAuth2AuthorizationConsent expectedAuthorizationConsent =
				OAuth2AuthorizationConsent.from(AUTHORIZATION_CONSENT)
						.authority(new SimpleGrantedAuthority("new.authority"))
						.build();
		when(registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);

		this.authorizationConsentService.save(expectedAuthorizationConsent);

		OAuth2AuthorizationConsent authorizationConsent =
				this.authorizationConsentService.findById(
						AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(authorizationConsent).isEqualTo(expectedAuthorizationConsent);
		assertThat(authorizationConsent).isNotEqualTo(AUTHORIZATION_CONSENT);
	}

	@Test
	public void saveLoadAuthorizationConsentWhenCustomStrategiesSetThenCalled() throws Exception {
		when(registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId())))
				.thenReturn(REGISTERED_CLIENT);

		JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentRowMapper authorizationConsentRowMapper = spy(
				new JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentRowMapper(
						this.registeredClientRepository));
		this.authorizationConsentService.setAuthorizationConsentRowMapper(authorizationConsentRowMapper);
		JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentParametersMapper authorizationConsentParametersMapper = spy(
				new JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentParametersMapper());
		this.authorizationConsentService.setAuthorizationConsentParametersMapper(authorizationConsentParametersMapper);

		this.authorizationConsentService.save(AUTHORIZATION_CONSENT);
		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService.findById(
				AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(authorizationConsent).isEqualTo(AUTHORIZATION_CONSENT);
		verify(authorizationConsentRowMapper).mapRow(any(), anyInt());
		verify(authorizationConsentParametersMapper).apply(any());
	}

	@Test
	public void removeWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizationConsentService.remove(null))
				.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void removeWhenAuthorizationConsentProvidedThenRemoved() {
		this.authorizationConsentService.remove(AUTHORIZATION_CONSENT);
		assertThat(this.authorizationConsentService.findById(
				AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName()))
				.isNull();
	}

	@Test
	public void findByIdWhenRegisteredClientIdNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizationConsentService.findById(null, "some-user"))
				.withMessage("registeredClientId cannot be empty");
	}

	@Test
	public void findByIdWhenPrincipalNameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizationConsentService.findById("some-client", null))
				.withMessage("principalName cannot be empty");
	}

	@Test
	public void findByIdWhenAuthorizationConsentDoesNotExistThenNull() {
		this.authorizationConsentService.save(AUTHORIZATION_CONSENT);
		assertThat(this.authorizationConsentService.findById("unknown-client", PRINCIPAL_NAME)).isNull();
		assertThat(this.authorizationConsentService.findById(REGISTERED_CLIENT.getId(), "unknown-user")).isNull();
	}

	@Before
	public void setUp() {
		this.db = createDb();
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.authorizationConsentService = new JdbcOAuth2AuthorizationConsentService(this.jdbcOperations, this.registeredClientRepository);
	}

	@After
	public void tearDown() {
		this.db.shutdown();
	}

	private static EmbeddedDatabase createDb() {
		return createDb(OAUTH2_AUTHORIZATION_CONSENT_SCHEMA_SQL_RESOURCE);
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
