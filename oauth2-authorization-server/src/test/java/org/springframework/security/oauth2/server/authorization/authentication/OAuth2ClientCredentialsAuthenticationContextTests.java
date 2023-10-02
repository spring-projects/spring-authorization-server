/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2ClientCredentialsAuthenticationContext}.
 *
 * @author Steve Riesenberg
 * @author Joe Grandja
 */
public class OAuth2ClientCredentialsAuthenticationContextTests {
	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
	private final OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient).build();
	private final Authentication principal = this.authorization.getAttribute(Principal.class.getName());
	private final OAuth2ClientCredentialsAuthenticationToken authorizationConsentAuthentication =
			new OAuth2ClientCredentialsAuthenticationToken(this.principal, Set.of("a_scope"), Map.of("a_key", "a_value"));

	@Test
	public void withWhenAuthenticationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2ClientCredentialsAuthenticationContext.with(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authentication cannot be null");
	}

	@Test
	public void setWhenValueNullThenThrowIllegalArgumentException() {
		OAuth2ClientCredentialsAuthenticationContext.Builder builder =
				OAuth2ClientCredentialsAuthenticationContext.with(this.authorizationConsentAuthentication);

		assertThatThrownBy(() -> builder.registeredClient(null))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> builder.put(null, ""))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenRequiredValueNullThenThrowIllegalArgumentException() {
		OAuth2ClientCredentialsAuthenticationContext.Builder builder =
				OAuth2ClientCredentialsAuthenticationContext.with(this.authorizationConsentAuthentication);
		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClient cannot be null");
	}

	@Test
	public void buildWhenAllValuesProvidedThenAllValuesAreSet() {
		OAuth2ClientCredentialsAuthenticationContext context =
				OAuth2ClientCredentialsAuthenticationContext.with(this.authorizationConsentAuthentication)
						.registeredClient(this.registeredClient)
						.put("custom-key-1", "custom-value-1")
						.context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
						.build();

		assertThat(context.<Authentication>getAuthentication()).isEqualTo(this.authorizationConsentAuthentication);
		assertThat(context.getRegisteredClient()).isEqualTo(this.registeredClient);
		assertThat(context.<String>get("custom-key-1")).isEqualTo("custom-value-1");
		assertThat(context.<String>get("custom-key-2")).isEqualTo("custom-value-2");
	}

}
