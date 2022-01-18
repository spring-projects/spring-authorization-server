/*
 * Copyright 2022 the original author or authors.
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

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientResource;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.jackson2.TestingAuthenticationTokenMixin;

import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerResourceMappers}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationServerResourceMappersTests {

	private final Function<RegisteredClient, RegisteredClientResource> registeredClientResourceMapper =
			OAuth2AuthorizationServerResourceMappers.registeredClientResourceMapper();
	private final Function<RegisteredClientResource, RegisteredClient> registeredClientMapper =
			OAuth2AuthorizationServerResourceMappers.registeredClientMapper();
	private final Function<OAuth2Authorization, OAuth2AuthorizationResource> authorizationResourceMapper =
			OAuth2AuthorizationServerResourceMappers.authorizationResourceMapper();
	private final Function<OAuth2AuthorizationResource, OAuth2Authorization> authorizationMapper =
			OAuth2AuthorizationServerResourceMappers.authorizationMapper();
	private final Function<OAuth2AuthorizationConsent, OAuth2AuthorizationConsentResource> authorizationConsentResourceMapper =
			OAuth2AuthorizationServerResourceMappers.authorizationConsentResourceMapper();
	private final Function<OAuth2AuthorizationConsentResource, OAuth2AuthorizationConsent> authorizationConsentMapper =
			OAuth2AuthorizationServerResourceMappers.authorizationConsentMapper();

	private ObjectMapper objectMapper;

	@Before
	public void setup() {
		ClassLoader classLoader = OAuth2AuthorizationServerResourceMappers.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		this.objectMapper = new ObjectMapper();
		this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
		this.objectMapper.registerModules(securityModules);
		this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		this.objectMapper.addMixIn(TestingAuthenticationToken.class, TestingAuthenticationTokenMixin.class);
	}

	@Test
	public void registeredClientMapperWhenMapperAppliedThenEquals() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClientResource registeredClientResource =
				this.registeredClientResourceMapper.apply(registeredClient);
		RegisteredClient registeredClient2 = this.registeredClientMapper.apply(registeredClientResource);
		assertThat(registeredClient).isEqualTo(registeredClient2);
	}

	@Test
	public void registeredClientMapperWhenConvertedToJsonThenEquals() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClientResource registeredClientResource = this.registeredClientResourceMapper.apply(registeredClient);
		String registeredClientJson = this.objectMapper.writeValueAsString(registeredClientResource);
		RegisteredClientResource registeredClientResource2 =
				this.objectMapper.readValue(registeredClientJson, RegisteredClientResource.class);
		RegisteredClient registeredClient2 = this.registeredClientMapper.apply(registeredClientResource2);
		assertThat(registeredClient).isEqualTo(registeredClient2);
	}

	@Test
	public void authorizationMapperWhenMapperAppliedThenEquals() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		OAuth2AuthorizationResource authorizationResource = this.authorizationResourceMapper.apply(authorization);
		OAuth2Authorization authorization2 = this.authorizationMapper.apply(authorizationResource);
		assertThat(authorization).isEqualTo(authorization2);
	}

	@Test
	public void authorizationMapperWhenConvertedToJsonThenEquals() throws Exception {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization()
				// Remove OAuth2AuthorizationRequest as it does not currently implement equals()
				// which fails the below assertion
				.attributes(attributes -> attributes.remove(OAuth2AuthorizationRequest.class.getName()))
				.build();
		OAuth2AuthorizationResource authorizationResource = this.authorizationResourceMapper.apply(authorization);
		String authorizationJson = this.objectMapper.writeValueAsString(authorizationResource);
		OAuth2AuthorizationResource authorizationResource2 =
				this.objectMapper.readValue(authorizationJson, OAuth2AuthorizationResource.class);
		OAuth2Authorization authorization2 = this.authorizationMapper.apply(authorizationResource2);
		assertThat(authorization).isEqualTo(authorization2);
	}

	@Test
	public void authorizationConsentMapperWhenMapperAppliedThenEquals() {
		OAuth2AuthorizationConsent authorizationConsent = OAuth2AuthorizationConsent.withId("client-1", "user1")
				.authority(new SimpleGrantedAuthority("some.authority"))
				.build();
		OAuth2AuthorizationConsentResource authorizationConsentResource =
				this.authorizationConsentResourceMapper.apply(authorizationConsent);
		OAuth2AuthorizationConsent authorizationConsent2 =
				this.authorizationConsentMapper.apply(authorizationConsentResource);
		assertThat(authorizationConsent).isEqualTo(authorizationConsent2);
	}

	@Test
	public void authorizationConsentMapperWhenConvertedToJsonThenEquals() throws Exception {
		OAuth2AuthorizationConsent authorizationConsent = OAuth2AuthorizationConsent.withId("client-1", "user1")
				.authority(new SimpleGrantedAuthority("some.authority"))
				.build();
		OAuth2AuthorizationConsentResource authorizationConsentResource =
				this.authorizationConsentResourceMapper.apply(authorizationConsent);
		String authorizationConsentJson = this.objectMapper.writeValueAsString(authorizationConsentResource);
		OAuth2AuthorizationConsentResource authorizationConsentResource2 =
				this.objectMapper.readValue(authorizationConsentJson, OAuth2AuthorizationConsentResource.class);
		OAuth2AuthorizationConsent authorizationConsent2 =
				this.authorizationConsentMapper.apply(authorizationConsentResource2);
		assertThat(authorizationConsent).isEqualTo(authorizationConsent2);
	}
}
