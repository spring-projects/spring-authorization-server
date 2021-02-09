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

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class TestOAuth2Authorizations {

	public static OAuth2Authorization.Builder authorization() {
		return authorization(TestRegisteredClients.registeredClient().build());
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient) {
		return authorization(registeredClient, Collections.emptyMap());
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
			Map<String, Object> authorizationRequestAdditionalParameters) {
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
				"code", Instant.now(), Instant.now().plusSeconds(120));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now(), Instant.now().plusSeconds(300));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken2(
				"refresh-token", Instant.now(), Instant.now().plus(1, ChronoUnit.HOURS));
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://provider.com/oauth2/authorize")
				.clientId(registeredClient.getClientId())
				.redirectUri(registeredClient.getRedirectUris().iterator().next())
				.scopes(registeredClient.getScopes())
				.additionalParameters(authorizationRequestAdditionalParameters)
				.state("state")
				.build();
		return OAuth2Authorization.withRegisteredClient(registeredClient)
				.id("id")
				.principalName("principal")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.token(authorizationCode)
				.token(accessToken, (metadata) -> metadata.putAll(tokenMetadata()))
				.refreshToken(refreshToken)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
				.attribute(Principal.class.getName(),
						new TestingAuthenticationToken("principal", null, "ROLE_A", "ROLE_B"))
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizationRequest.getScopes());
	}

	private static Map<String, Object> tokenMetadata() {
		Map<String, Object> tokenMetadata = new HashMap<>();
		tokenMetadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
		Map<String, Object> claims = new HashMap<>();
		claims.put("claim1", "value1");
		claims.put("claim2", "value2");
		claims.put("claim3", "value3");
		tokenMetadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
		return tokenMetadata;
	}
}
