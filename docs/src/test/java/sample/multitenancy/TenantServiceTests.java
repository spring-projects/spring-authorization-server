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
package sample.multitenancy;

import java.util.List;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link TenantService}.
 *
 * @author Steve Riesenberg
 */
public class TenantServiceTests {

	private static final String ISSUER1 = "http://localhost:9000/issuer1";

	private static final String ISSUER2 = "http://localhost:9000/issuer2";

	private AuthorizationServerContext authorizationServerContext;

	private TenantPerIssuerComponentRegistry componentRegistry;

	private TenantService tenantService;

	@BeforeEach
	public void setUp() {
		this.authorizationServerContext = mock(AuthorizationServerContext.class);
		this.componentRegistry = new TenantPerIssuerComponentRegistry();
		this.tenantService = new TenantService(this.componentRegistry);

		AuthorizationServerContextHolder.setContext(this.authorizationServerContext);
	}

	@AfterEach
	public void tearDown() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void testCreateTenantWhenMultipleIssuersThenCreated() {
		this.tenantService.createTenant("issuer1");
		this.tenantService.createTenant("issuer2");

		for (String issuer : List.of(ISSUER1, ISSUER2)) {
			when(this.authorizationServerContext.getIssuer()).thenReturn(issuer);
			assertThat(this.componentRegistry.get(RegisteredClientRepository.class))
					.isInstanceOf(JdbcRegisteredClientRepository.class);
			assertThat(this.componentRegistry.get(OAuth2AuthorizationService.class))
					.isInstanceOf(JdbcOAuth2AuthorizationService.class);
			assertThat(this.componentRegistry.get(OAuth2AuthorizationConsentService.class))
					.isInstanceOf(JdbcOAuth2AuthorizationConsentService.class);
			assertThat(this.componentRegistry.get(JWKSet.class)).isNotNull();
		}
	}

}
