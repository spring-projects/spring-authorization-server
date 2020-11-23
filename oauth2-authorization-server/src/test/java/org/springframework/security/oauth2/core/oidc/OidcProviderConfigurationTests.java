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
package org.springframework.security.oauth2.core.oidc;

import org.junit.Test;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OidcProviderConfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OidcProviderConfigurationTests {
	private final OidcProviderConfiguration.Builder minimalConfigurationBuilder =
			OidcProviderConfiguration.withClaims()
					.issuer("https://example.com/issuer1")
					.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
					.tokenEndpoint("https://example.com/issuer1/oauth2/token")
					.jwksUri("https://example.com/issuer1/oauth2/jwks")
					.scope("openid")
					.responseType("code")
					.subjectType("public");

	@Test
	public void buildWhenAllRequiredClaimsAndAdditionalClaimsThenCreated() {
		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.withClaims()
				.issuer("https://example.com/issuer1")
				.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
				.tokenEndpoint("https://example.com/issuer1/oauth2/token")
				.jwksUri("https://example.com/issuer1/oauth2/jwks")
				.scope("openid")
				.responseType("code")
				.grantType("authorization_code")
				.grantType("client_credentials")
				.subjectType("public")
				.tokenEndpointAuthenticationMethod("client_secret_basic")
				.claim("a-claim", "a-value")
				.build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(providerConfiguration.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(providerConfiguration.getJwksUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "client_credentials");
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).containsExactly("client_secret_basic");
		assertThat(providerConfiguration.<String>getClaim("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void buildWhenOnlyRequiredClaimsThenCreated() {
		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.withClaims()
				.issuer("https://example.com/issuer1")
				.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
				.tokenEndpoint("https://example.com/issuer1/oauth2/token")
				.jwksUri("https://example.com/issuer1/oauth2/jwks")
				.scope("openid")
				.responseType("code")
				.subjectType("public")
				.build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(providerConfiguration.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(providerConfiguration.getJwksUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
	}

	@Test
	public void buildWhenClaimsProvidedThenCreated() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OidcProviderMetadataClaimNames.ISSUER, "https://example.com/issuer1");
		claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, "https://example.com/issuer1/oauth2/authorize");
		claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, "https://example.com/issuer1/oauth2/token");
		claims.put(OidcProviderMetadataClaimNames.JWKS_URI, "https://example.com/issuer1/oauth2/jwks");
		claims.put(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, Collections.singletonList("openid"));
		claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singletonList("code"));
		claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.singletonList("public"));
		claims.put("some-claim", "some-value");

		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.withClaims(claims).build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(providerConfiguration.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(providerConfiguration.getJwksUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(providerConfiguration.<String>getClaim("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void buildWhenClaimsProvidedWithUrlsThenCreated() {
		Map<String, Object> claims = new HashMap<>();
		claims.put(OidcProviderMetadataClaimNames.ISSUER, url("https://example.com/issuer1"));
		claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, url("https://example.com/issuer1/oauth2/authorize"));
		claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, url("https://example.com/issuer1/oauth2/token"));
		claims.put(OidcProviderMetadataClaimNames.JWKS_URI, url("https://example.com/issuer1/oauth2/jwks"));
		claims.put(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, Collections.singletonList("openid"));
		claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singletonList("code"));
		claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.singletonList("public"));
		claims.put("some-claim", "some-value");

		OidcProviderConfiguration providerConfiguration = OidcProviderConfiguration.withClaims(claims).build();

		assertThat(providerConfiguration.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(providerConfiguration.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(providerConfiguration.getJwksUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(providerConfiguration.<String>getClaim("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void withClaimsWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OidcProviderConfiguration.withClaims(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void withClaimsWhenMissingRequiredClaimsThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OidcProviderConfiguration.withClaims(Collections.emptyMap()))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoConfigurations() {
		OidcProviderConfiguration first = this.minimalConfigurationBuilder
				.grantType("client_credentials")
				.build();

		OidcProviderConfiguration second = this.minimalConfigurationBuilder
				.claims((claims) ->
						{
							Set<String> newGrantTypes = new LinkedHashSet<>();
							newGrantTypes.add("authorization_code");
							newGrantTypes.add("custom_grant");
							claims.put(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, newGrantTypes);
						}
				)
				.build();

		assertThat(first.getGrantTypes()).containsExactly("client_credentials");
		assertThat(second.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "custom_grant");
	}

	@Test
	public void buildWhenMissingIssuerThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.ISSUER));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("issuer cannot be null");
	}

	@Test
	public void buildWhenIssuerNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.ISSUER, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("issuer must be a valid URL");
	}

	@Test
	public void buildWhenMissingAuthorizationEndpointThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationEndpoint cannot be null");
	}

	@Test
	public void buildWhenAuthorizationEndpointNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("authorizationEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingTokenEndpointThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenEndpoint cannot be null");
	}

	@Test
	public void buildWhenTokenEndpointNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("tokenEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingJwksUriThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.JWKS_URI));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwksUri cannot be null");
	}

	@Test
	public void buildWhenJwksUriNotUrlThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.JWKS_URI, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("jwksUri must be a valid URL");
	}

	@Test
	public void buildWhenMissingResponseTypesThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("responseTypes cannot be null");
	}

	@Test
	public void buildWhenResponseTypesNotListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> {
					claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
					claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, "code");
				});

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("responseTypes must be of type List");
	}

	@Test
	public void buildWhenResponseTypesEmptyListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> {
					claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED);
					claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.emptyList());
				});

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("responseTypes cannot be empty");
	}

	@Test
	public void buildWhenMissingSubjectTypesThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("subjectTypes cannot be null");
	}

	@Test
	public void buildWhenSubjectTypesNotListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> {
					claims.remove(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
					claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, "public");
				});

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("subjectTypes must be of type List");
	}

	@Test
	public void buildWhenSubjectTypesEmptyListThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> {
					claims.remove(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
					claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.emptyList());
				});

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("subjectTypes cannot be empty");
	}

	@Test
	public void responseTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
				.responseType("should-be-removed")
				.responseTypes(responseTypes -> {
					responseTypes.clear();
					responseTypes.add("some-response-type");
				})
				.build();

		assertThat(configuration.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void responseTypesWhenNotPresentAndAddingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
				.claims(claims -> claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED))
				.responseTypes(responseTypes -> responseTypes.add("some-response-type"))
				.build();

		assertThat(configuration.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void subjectTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
				.subjectType("should-be-removed")
				.subjectTypes(subjectTypes -> {
					subjectTypes.clear();
					subjectTypes.add("some-subject-type");
				})
				.build();

		assertThat(configuration.getSubjectTypes()).containsExactly("some-subject-type");
	}

	@Test
	public void scopesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
				.scope("should-be-removed")
				.scopes(scopes -> {
					scopes.clear();
					scopes.add("some-scope");
				})
				.build();

		assertThat(configuration.getScopes()).containsExactly("some-scope");
	}

	@Test
	public void grantTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
				.grantType("should-be-removed")
				.grantTypes(grantTypes -> {
					grantTypes.clear();
					grantTypes.add("some-grant-type");
				})
				.build();

		assertThat(configuration.getGrantTypes()).containsExactly("some-grant-type");
	}

	@Test
	public void tokenEndpointAuthenticationMethodsWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = this.minimalConfigurationBuilder
				.tokenEndpointAuthenticationMethod("should-be-removed")
				.tokenEndpointAuthenticationMethods(authMethods -> {
					authMethods.clear();
					authMethods.add("some-authentication-method");
				})
				.build();

		assertThat(configuration.getTokenEndpointAuthenticationMethods()).containsExactly("some-authentication-method");
	}

	@Test
	public void claimWhenNameIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OidcProviderConfiguration.withClaims().claim(null, "value"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OidcProviderConfiguration.withClaims().claim("claim-name", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void claimsWhenRemovingClaimThenNotPresent() {
		OidcProviderConfiguration configuration =
				this.minimalConfigurationBuilder
						.grantType("some-grant-type")
						.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED))
						.build();
		assertThat(configuration.getGrantTypes()).isNull();
	}

	@Test
	public void claimsWhenAddingClaimThenPresent() {
		OidcProviderConfiguration configuration =
				this.minimalConfigurationBuilder
						.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, "authorization_code"))
						.build();
		assertThat(configuration.getGrantTypes()).containsExactly("authorization_code");
	}

	private static URL url(String urlString) {
		try {
			return new URL(urlString);
		} catch (Exception ex) {
			throw new IllegalArgumentException("urlString must be a valid URL and valid URI");
		}
	}
}
