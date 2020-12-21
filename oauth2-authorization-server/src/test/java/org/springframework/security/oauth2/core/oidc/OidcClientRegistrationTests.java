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
package org.springframework.security.oauth2.core.oidc;

import org.junit.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OidcClientRegistration}
 *
 * @author Ovidiu Popa
 * @since 0.1.1
 */
public class OidcClientRegistrationTests {

	private final OidcClientRegistration.Builder clientRegistrationBuilder =
			OidcClientRegistration.builder();

	@Test
	public void buildWhenAllRequiredClaimsAndAdditionalClaimsThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.scope("test read")
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.BASIC.getValue())
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getGrantTypes())
				.contains(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()
				);
		assertThat(clientRegistration.getResponseTypes())
				.contains(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistration.getScope())
				.isEqualTo("test read");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.BASIC.getValue());

	}

	@Test
	public void buildWhenAllRequiredClaimsThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getGrantTypes())
				.containsOnly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(clientRegistration.getResponseTypes())
				.containsOnly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistration.getScope())
				.isNull();
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.BASIC.getValue());
	}

	@Test
	public void buildWhenAllRequiredClaimsAndAuthorizationGrantTypeButMissingResponseTypeThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getGrantTypes())
				.containsOnly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(clientRegistration.getResponseTypes())
				.containsOnly(OAuth2AuthorizationResponseType.CODE.getValue());
	}

	@Test
	public void buildWhenAllRequiredClaimsAndEmptyGrantTypeListButMissingResponseTypeThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.grantTypes(List::clear)
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getGrantTypes())
				.containsOnly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(clientRegistration.getResponseTypes())
				.containsOnly(OAuth2AuthorizationResponseType.CODE.getValue());
	}

	@Test
	public void buildWhenAllRequiredClaimsAndResponseTypeButMissingAuthorizationGrantTypeThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getGrantTypes())
				.containsOnly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(clientRegistration.getResponseTypes())
				.containsOnly(OAuth2AuthorizationResponseType.CODE.getValue());
	}

	@Test
	public void buildWhenAllRequiredClaimsAndEmptyResponseTypeListButMissingAuthorizationGrantTypeThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.responseTypes(List::clear)
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getGrantTypes())
				.containsOnly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(clientRegistration.getResponseTypes())
				.containsOnly(OAuth2AuthorizationResponseType.CODE.getValue());
	}

	@Test
	public void buildWhenAllRequiredClaimsAndEmptyScopeThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getScope())
				.isNull();
	}

	@Test
	public void buildWhenAllRequiredClaimsAndEmptyTokenEndpointAuthMethodThenCreated() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com")
				.build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.BASIC.getValue());
	}

	@Test
	public void buildWhenClaimsProvidedThenCreated() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OidcClientMetadataClaimNames.REDIRECT_URIS, Collections.singletonList("http://client.example.com"));
		claims.put(OidcClientMetadataClaimNames.GRANT_TYPES, Arrays.asList(
				AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
				AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()
		));
		claims.put(OidcClientMetadataClaimNames.RESPONSE_TYPES,
				Collections.singletonList(OAuth2AuthorizationResponseType.CODE.getValue()));
		claims.put(OidcClientMetadataClaimNames.SCOPE, "test read");
		claims.put(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, ClientAuthenticationMethod.BASIC.getValue());

		OidcClientRegistration clientRegistration = OidcClientRegistration.withClaims(claims).build();

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("http://client.example.com");
		assertThat(clientRegistration.getGrantTypes())
				.contains(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()
				);
		assertThat(clientRegistration.getResponseTypes())
				.contains(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistration.getScope())
				.isEqualTo("test read");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.BASIC.getValue());
	}

	@Test
	public void buildWhenRedirectUriProvidedWithUrlThenCreated() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OidcClientMetadataClaimNames.REDIRECT_URIS, Arrays.asList(
				url("http://client.example.com"),
				url("http://client.example.com/authorized")
				)
		);
		claims.put(OidcClientMetadataClaimNames.GRANT_TYPES, Arrays.asList(
				AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
				AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()
		));
		claims.put(OidcClientMetadataClaimNames.RESPONSE_TYPES,
				Collections.singletonList(OAuth2AuthorizationResponseType.CODE.getValue()));
		claims.put(OidcClientMetadataClaimNames.SCOPE, "test read");
		claims.put(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, ClientAuthenticationMethod.BASIC.getValue());

		OidcClientRegistration clientRegistration = OidcClientRegistration.withClaims(claims).build();

		assertThat(clientRegistration.getRedirectUris())
				.contains("http://client.example.com", "http://client.example.com/authorized");
		assertThat(clientRegistration.getGrantTypes())
				.contains(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()
				);
		assertThat(clientRegistration.getResponseTypes())
				.contains(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistration.getScope())
				.isEqualTo("test read");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.BASIC.getValue());
	}

	@Test
	public void withClaimsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OidcClientRegistration.withClaims(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void withClaimsEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OidcClientRegistration.withClaims(Collections.emptyMap()))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenNullRedirectUriThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.clientRegistrationBuilder
				.redirectUris((claims) -> claims.remove(OidcClientMetadataClaimNames.REDIRECT_URIS));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("redirect_uris must not be empty");
	}

	@Test
	public void buildWhenNullRedirectUriClaimThenThrowIllegalArgumentException() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OidcClientMetadataClaimNames.REDIRECT_URIS, null);
		OidcClientRegistration.Builder builder = OidcClientRegistration.withClaims(claims);

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("redirect_uris cannot be null");
	}

	@Test
	public void buildWhenEmptyRedirectUriListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.clientRegistrationBuilder
				.redirectUris(List::clear);

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("redirect_uris must not be empty");
	}

	@Test
	public void buildWhenRedirectUriNotOfTypeListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.clientRegistrationBuilder
				.claims(claims -> claims.put(OidcClientMetadataClaimNames.REDIRECT_URIS, "http://client.example.com"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("redirect_uris must be of type list");
	}

	@Test
	public void buildWhenRedirectUriNotUrlThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.clientRegistrationBuilder
				.redirectUri("not url");

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("redirect_uri must be a valid URL");
	}

	@Test
	public void buildWhenResponseTypesNotOfTypeListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.clientRegistrationBuilder
				.redirectUri("http://client.example.com")
				.claims(claims -> claims.put(OidcClientMetadataClaimNames.RESPONSE_TYPES, OAuth2AuthorizationResponseType.CODE.getValue()));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("response_types must be of type List");
	}

	@Test
	public void buildWhenGrantTypesNotOfTypeListThenThrowIllegalArgumentException() {
		OidcClientRegistration.Builder builder = this.clientRegistrationBuilder
				.redirectUri("http://client.example.com")
				.claims(claims -> claims.put(OidcClientMetadataClaimNames.GRANT_TYPES, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("grant_types must be of type List");
	}

	private static URL url(String urlString) {
		try {
			return new URL(urlString);
		} catch (Exception ex) {
			throw new IllegalArgumentException("urlString must be a valid URL and valid URI");
		}
	}

}
