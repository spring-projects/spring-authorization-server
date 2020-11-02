/*
 * Copyright 2020 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.token;

import java.util.Collections;
import java.util.Set;

import org.junit.Test;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

/**
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class OAuth2AuthorizationGrantContextTest {

	@Test
	public void issueWhenNoResourceOwnerThenThrowException() {
		OAuth2AuthorizationGrantContext.Builder tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.principalName(null);

		assertThatThrownBy(tokenRequest::build)
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("principalName cannot be null");
	}

	@Test
	public void issueWhenNoRegisteredClientThenThrowException() {
		OAuth2AuthorizationGrantContext.Builder tokenRequest = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.registeredClient(null);

		assertThatThrownBy(tokenRequest::build)
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("registeredClient cannot be null");
	}

	@Test
	public void builderWhenBuildThenSetResourceOwner() {
		String testPrincipalName = "test-user";
		OAuth2AuthorizationGrantContext request = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.principalName(testPrincipalName)
				.build();

		assertThat(request.getPrincipalName()).isEqualTo(testPrincipalName);
	}

	@Test
	public void builderWhenBuildThenSetRegisteredClient() {
		RegisteredClient client = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationGrantContext request = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.registeredClient(client)
				.build();

		assertThat(request.getRegisteredClient()).isEqualTo(client);
	}

	@Test
	public void builderWhenBuildThenSetClaims() {
		Set<String> expectedScopes = Collections.singleton("test-scope");
		OAuth2AuthorizationGrantContext request = TestOAuth2TokenAuthorizationGrantContexts.validContext()
				.claims(Collections.singletonMap("scope", expectedScopes))
				.claim("another-claim", "claim-value")
				.build();

		assertThat(request.getClaims()).containsEntry("scope", expectedScopes);
		assertThat(request.getClaims()).containsEntry("another-claim", "claim-value");
	}
}
