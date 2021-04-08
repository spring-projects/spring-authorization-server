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

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2AuthorizationConsent}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationConsentTest {
	@Test
	public void fromWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationConsent.from(null))
				.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void withClientIdAndPrincipalWhenClientIdNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationConsent.withId(null, "some-user"))
				.withMessage("registeredClientId cannot be empty");
	}

	@Test
	public void withClientIdAndPrincipalWhenPrincipalNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationConsent.withId("some-client", null))
				.withMessage("principalName cannot be empty");
	}

	@Test
	public void buildWhenAuthoritiesEmptyThenThrowIllegalArgumentException() {
		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId("some-client", "some-user");
		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("authorities cannot be empty");
	}

	@Test
	public void buildWhenAllAttributesAreProvidedThenAllAttributesAreSet() {
		OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent
				.withId("some-client", "some-user")
				.scope("resource.read")
				.scope("resource.write")
				.authority(new SimpleGrantedAuthority("CLAIM_email"))
				.build();

		assertThat(consent.getPrincipalName()).isEqualTo("some-user");
		assertThat(consent.getRegisteredClientId()).isEqualTo("some-client");
		assertThat(consent.getScopes())
				.containsExactlyInAnyOrder(
						"resource.read",
						"resource.write"
				);
		assertThat(consent.getAuthorities())
				.containsExactlyInAnyOrder(
						new SimpleGrantedAuthority("SCOPE_resource.read"),
						new SimpleGrantedAuthority("SCOPE_resource.write"),
						new SimpleGrantedAuthority("CLAIM_email")
				);
	}

	@Test
	public void fromWhenAuthorizationConsentProvidedThenCopied() {
		OAuth2AuthorizationConsent previousConsent = OAuth2AuthorizationConsent
				.withId("some-client", "some-principal")
				.scope("first.scope")
				.scope("second.scope")
				.authority(new SimpleGrantedAuthority("CLAIM_email"))
				.build();

		OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.from(previousConsent).build();

		assertThat(consent.getPrincipalName()).isEqualTo("some-principal");
		assertThat(consent.getRegisteredClientId()).isEqualTo("some-client");
		assertThat(consent.getAuthorities())
				.containsExactlyInAnyOrder(
						new SimpleGrantedAuthority("SCOPE_first.scope"),
						new SimpleGrantedAuthority("SCOPE_second.scope"),
						new SimpleGrantedAuthority("CLAIM_email")
				);
	}

	@Test
	public void authoritiesThenCustomizesAuthorities() {
		OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent
				.withId("some-client", "some-user")
				.authority(new SimpleGrantedAuthority("some.authority"))
				.authorities(authorities -> {
					authorities.clear();
					authorities.add(new SimpleGrantedAuthority("other.authority"));
				})
				.build();

		assertThat(consent.getAuthorities()).containsExactly(new SimpleGrantedAuthority("other.authority"));
	}
}
