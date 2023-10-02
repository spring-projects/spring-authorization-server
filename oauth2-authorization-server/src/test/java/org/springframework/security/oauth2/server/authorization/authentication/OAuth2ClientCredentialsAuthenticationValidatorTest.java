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

import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients.SCOPE_1;
import static org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients.SCOPE_2;

public class OAuth2ClientCredentialsAuthenticationValidatorTest {
	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
	private final OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient).build();
	private final Authentication principal = this.authorization.getAttribute(Principal.class.getName());
	private final OAuth2ClientCredentialsAuthenticationValidator validator = new OAuth2ClientCredentialsAuthenticationValidator();

	@ParameterizedTest
	@MethodSource("validScopes")
	public void acceptWhenRequestScopesAreEmptyOrValidThenDoesNotThrowException(Set<String> testScopes) {
		OAuth2ClientCredentialsAuthenticationToken token =
				new OAuth2ClientCredentialsAuthenticationToken(this.principal, testScopes, Map.of());
		OAuth2ClientCredentialsAuthenticationContext context = OAuth2ClientCredentialsAuthenticationContext.with(token).registeredClient(registeredClient).build();

		assertThatNoException().isThrownBy(() -> validator.accept(context));
	}

	@Test
	public void acceptWhenRequestScopesAreNotAllValidThenThrowException() {
		OAuth2ClientCredentialsAuthenticationToken token =
				new OAuth2ClientCredentialsAuthenticationToken(this.principal, Set.of(SCOPE_1, SCOPE_2), Map.of());
		OAuth2ClientCredentialsAuthenticationContext context = OAuth2ClientCredentialsAuthenticationContext.with(token).registeredClient(registeredClient).build();

		assertThatThrownBy(() -> validator.accept(context))
				.isInstanceOfSatisfying(OAuth2ClientCredentialsAuthenticationException.class,
						t -> assertThat(t.getClientCredentialsAuthentication()).isEqualTo(token));
	}

	static Stream<Arguments> validScopes() {
		return Stream.of(Arguments.of(new HashSet<>()), Arguments.of(Set.of(SCOPE_1)));
	}
}
