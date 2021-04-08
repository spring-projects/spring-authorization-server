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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link InMemoryOAuth2AuthorizationConsentService}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryOAuth2AuthorizationConsentServiceTest {
	private InMemoryOAuth2AuthorizationConsentService consentService;

	private static final String CLIENT_ID = "client-id";
	private static final String PRINCIPAL_NAME = "principal-name";
	private static final OAuth2AuthorizationConsent CONSENT = OAuth2AuthorizationConsent
			.withId(CLIENT_ID, PRINCIPAL_NAME)
			.authority(new SimpleGrantedAuthority("some.authority"))
			.build();

	@Before
	public void setUp() throws Exception {
		this.consentService = new InMemoryOAuth2AuthorizationConsentService();
		this.consentService.save(CONSENT);
	}

	@Test
	public void constructorVaragsWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new InMemoryOAuth2AuthorizationConsentService((OAuth2AuthorizationConsent) null))
				.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void constructorListWhenAuthorizationConsentsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new InMemoryOAuth2AuthorizationConsentService((List<OAuth2AuthorizationConsent>) null))
				.withMessage("authorizationConsents cannot be null");
	}

	@Test
	public void constructorWhenDuplicateAuthorizationConsentsThenThrowIllegalArgumentException() {
		OAuth2AuthorizationConsent authorizationConsent = OAuth2AuthorizationConsent.withId("client-id", "principal-name")
				.scope("thing.write") // must have at least one scope
				.build();

		assertThatIllegalArgumentException()
				.isThrownBy(() -> new InMemoryOAuth2AuthorizationConsentService(authorizationConsent, authorizationConsent))
				.withMessage("The authorizationConsent must be unique. Found duplicate, with registered client id: [client-id] and principal name: [principal-name]");
	}

	@Test
	public void saveWhenConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.consentService.save(null))
				.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void saveWhenConsentNewThenSaved() {
		OAuth2AuthorizationConsent expectedConsent = OAuth2AuthorizationConsent
				.withId("new-client", "new-principal")
				.authority(new SimpleGrantedAuthority("new.authority"))
				.build();

		this.consentService.save(expectedConsent);

		OAuth2AuthorizationConsent consent =
				this.consentService.findById("new-client", "new-principal");
		assertThat(consent).isEqualTo(expectedConsent);
	}

	@Test
	public void saveWhenConsentExistsThenUpdated() {
		OAuth2AuthorizationConsent expectedConsent = OAuth2AuthorizationConsent
				.from(CONSENT)
				.authority(new SimpleGrantedAuthority("new.authority"))
				.build();

		this.consentService.save(expectedConsent);

		OAuth2AuthorizationConsent consent =
				this.consentService.findById(CLIENT_ID, PRINCIPAL_NAME);
		assertThat(consent).isEqualTo(expectedConsent);
		assertThat(consent).isNotEqualTo(CONSENT);

	}

	@Test
	public void removeNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.consentService.remove(null))
				.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void removeWhenConsentProvidedThenRemoved() {
		this.consentService.remove(CONSENT);

		assertThat(this.consentService.findById(CLIENT_ID, PRINCIPAL_NAME))
				.isNull();
	}

	@Test
	public void findWhenRegisteredClientIdNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.consentService.findById(null, "some-user"))
				.withMessage("registeredClientId cannot be empty");
	}

	@Test
	public void findWhenPrincipalNameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.consentService.findById("some-client", null))
				.withMessage("principalName cannot be empty");
	}

	@Test
	public void findWhenConsentExistsThenFound() {
		assertThat(this.consentService.findById(CLIENT_ID, PRINCIPAL_NAME))
				.isEqualTo(CONSENT);
	}

	@Test
	public void findWhenConsentDoesNotExistThenNull() {
		this.consentService.save(CONSENT);

		assertThat(this.consentService.findById("unknown-client", PRINCIPAL_NAME)).isNull();
		assertThat(this.consentService.findById(CLIENT_ID, "unkown-user")).isNull();
	}
}
