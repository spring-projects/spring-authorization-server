/*
 * Copyright 2020-2024 the original author or authors.
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultOAuth2TokenClaimsConsumer}.
 *
 * @author Steve Riesenberg
 */
public class DefaultOAuth2TokenClaimsConsumerTests {

	private OAuth2TokenContext tokenContext;

	private Consumer<Map<String, Object>> consumer;

	@BeforeEach
	public void setUp() {
		this.tokenContext = mock(OAuth2TokenContext.class);
		this.consumer = new DefaultOAuth2TokenClaimsConsumer(this.tokenContext);
	}

	@Test
	public void acceptWhenTokenTypeIsRefreshTokenThenNoClaimsAdded() {
		when(this.tokenContext.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
		Map<String, Object> claims = new LinkedHashMap<>();
		this.consumer.accept(claims);
		assertThat(claims).isEmpty();
	}

	@Test
	public void acceptWhenAuthorizationGrantIsNullThenNoClaimsAdded() {
		when(this.tokenContext.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
		when(this.tokenContext.getAuthorizationGrant()).thenReturn(null);
		Map<String, Object> claims = new LinkedHashMap<>();
		this.consumer.accept(claims);
		assertThat(claims).isEmpty();
	}

	@Test
	public void acceptWhenTokenExchangeGrantAndResourcesThenNoClaimsAdded() {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = mock(
				OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getResources()).thenReturn(Set.of("resource1", "resource2"));
		when(this.tokenContext.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
		when(this.tokenContext.getAuthorizationGrant()).thenReturn(tokenExchangeAuthentication);
		Map<String, Object> claims = new LinkedHashMap<>();
		this.consumer.accept(claims);
		// We do not populate claims (e.g. `aud`) based on the resource parameter
		assertThat(claims).isEmpty();
	}

	@Test
	public void acceptWhenTokenExchangeGrantAndAudiencesThenNoClaimsAdded() {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = mock(
				OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getAudiences()).thenReturn(Set.of("audience1", "audience2"));
		when(this.tokenContext.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
		when(this.tokenContext.getAuthorizationGrant()).thenReturn(tokenExchangeAuthentication);
		Map<String, Object> claims = new LinkedHashMap<>();
		this.consumer.accept(claims);
		// NOTE: We do not populate claims (e.g. `aud`) based on the audience parameter
		assertThat(claims).isEmpty();
	}

	@Test
	public void acceptWhenTokenExchangeGrantAndDelegationThenActClaimAdded() {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication = mock(
				OAuth2TokenExchangeAuthenticationToken.class);
		when(tokenExchangeAuthentication.getAudiences()).thenReturn(Collections.emptySet());
		when(this.tokenContext.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
		when(this.tokenContext.getAuthorizationGrant()).thenReturn(tokenExchangeAuthentication);
		Authentication subject = new TestingAuthenticationToken("subject", null);
		OAuth2TokenExchangeActor actor1 = new OAuth2TokenExchangeActor(Map.of(OAuth2TokenClaimNames.ISS, "issuer1",
				OAuth2TokenClaimNames.SUB, "actor1"));
		OAuth2TokenExchangeActor actor2 = new OAuth2TokenExchangeActor(Map.of(OAuth2TokenClaimNames.ISS, "issuer2",
				OAuth2TokenClaimNames.SUB, "actor2"));
		OAuth2TokenExchangeCompositeAuthenticationToken principal = new OAuth2TokenExchangeCompositeAuthenticationToken(
				subject, List.of(actor1, actor2));
		when(this.tokenContext.getPrincipal()).thenReturn(principal);
		Map<String, Object> claims = new LinkedHashMap<>();
		this.consumer.accept(claims);
		assertThat(claims).hasSize(1);
		assertThat(claims.get("act")).isNotNull();
		@SuppressWarnings("unchecked")
		Map<String, Object> actClaim1 = (Map<String, Object>) claims.get("act");
		assertThat(actClaim1.get(OAuth2TokenClaimNames.ISS)).isEqualTo("issuer1");
		assertThat(actClaim1.get(OAuth2TokenClaimNames.SUB)).isEqualTo("actor1");
		@SuppressWarnings("unchecked")
		Map<String, Object> actClaim2 = (Map<String, Object>) actClaim1.get("act");
		assertThat(actClaim2.get(OAuth2TokenClaimNames.ISS)).isEqualTo("issuer2");
		assertThat(actClaim2.get(OAuth2TokenClaimNames.SUB)).isEqualTo("actor2");
	}

}
