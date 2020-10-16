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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;

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
				.tokenEndpointAuthenticationMethod("basic")
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
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).containsExactly("basic");
		assertThat(providerConfiguration.getClaimAsString("a-claim")).isEqualTo("a-value");
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
	public void buildFromClaimsThenCreated() {
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OidcProviderMetadataClaimNames.ISSUER, "https://example.com/issuer1");
		claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, "https://example.com/issuer1/oauth2/authorize");
		claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, "https://example.com/issuer1/oauth2/token");
		claims.put(OidcProviderMetadataClaimNames.JWKS_URI, "https://example.com/issuer1/oauth2/jwks");
		claims.put(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, Collections.singleton("openid"));
		claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singleton("code"));
		claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.singleton("public"));
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
		assertThat(providerConfiguration.getClaimAsString("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void buildFromClaimsWhenUsingUrlsThenCreated() {
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OidcProviderMetadataClaimNames.ISSUER, url("https://example.com/issuer1"));
		claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, url("https://example.com/issuer1/oauth2/authorize"));
		claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, url("https://example.com/issuer1/oauth2/token"));
		claims.put(OidcProviderMetadataClaimNames.JWKS_URI, url("https://example.com/issuer1/oauth2/jwks"));
		claims.put(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, Collections.singleton("openid"));
		claims.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singleton("code"));
		claims.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, Collections.singleton("public"));
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
		assertThat(providerConfiguration.getClaimAsString("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void withClaimsWhenNullThenThrowsException() {
		assertThatThrownBy(() -> OidcProviderConfiguration.withClaims(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void  withClaimsWhenMissingRequiredClaimsThenThrowsException() {
		assertThatThrownBy(() -> OidcProviderConfiguration.withClaims(Collections.emptyMap()))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoConfigurations() {
		OidcProviderConfiguration first = minimalConfigurationBuilder
				.grantType("client_credentials")
				.build();

		OidcProviderConfiguration second = minimalConfigurationBuilder
				.claims((claims) ->
						{
							LinkedHashSet<String> newGrantTypes = new LinkedHashSet<>();
							newGrantTypes.add("authorization_code");
							newGrantTypes.add("implicit");
							claims.put(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, newGrantTypes);
						}
				)
				.build();

		assertThat(first.getGrantTypes()).containsExactly("client_credentials");
		assertThat(second.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "implicit");
	}

	@Test
	public void buildWhenMissingIssuerThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.ISSUER));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("issuer cannot be null");
	}

	@Test
	public void buildWhenIssuerIsNotAnUrlThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.ISSUER, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("issuer must be a valid URL");
	}

	@Test
	public void buildWhenMissingAuthorizationEndpointThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationEndpoint cannot be null");
	}

	@Test
	public void buildWhenAuthorizationEndpointIsNotAnUrlThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("authorizationEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingTokenEndpointThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("tokenEndpoint cannot be null");
	}

	@Test
	public void buildWhenTokenEndpointIsNotAnUrlThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("tokenEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingJwksUriThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.JWKS_URI));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwkSetUri cannot be null");
	}

	@Test
	public void buildWheJwksUriIsNotAnUrlThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.JWKS_URI, "not an url"));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("jwkSetUri must be a valid URL");
	}

	@Test
	public void buildWhenMissingResponseTypesThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("responseTypes cannot be empty");
	}

	@Test
	public void buildWhenMissingSubjectTypesThenThrowsException() {
		OidcProviderConfiguration.Builder builder = minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED));

		assertThatThrownBy(builder::build)
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("subjectTypes cannot be empty");
	}

	@Test
	public void responseTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = minimalConfigurationBuilder
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
		OidcProviderConfiguration configuration = minimalConfigurationBuilder
				.claims(claims -> claims.remove(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED))
				.responseTypes(responseTypes -> responseTypes.add("some-response-type"))
				.build();

		assertThat(configuration.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void subjectTypesWhenAddingOrRemovingThenCorrectValues() {
		OidcProviderConfiguration configuration = minimalConfigurationBuilder
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
		OidcProviderConfiguration configuration = minimalConfigurationBuilder
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
		OidcProviderConfiguration configuration = minimalConfigurationBuilder
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
		OidcProviderConfiguration configuration = minimalConfigurationBuilder
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
		OidcProviderConfiguration.Builder builder = OidcProviderConfiguration.withClaims();
		assertThatThrownBy(() -> builder.claim(null, "value"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueIsNullThenThrowIllegalArgumentException() {
		OidcProviderConfiguration.Builder builder = OidcProviderConfiguration.withClaims();
		assertThatThrownBy(() -> builder.claim("claim-name", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void claimsWhenRemovingAClaimThenIsNotPresent() {
		OidcProviderConfiguration configuration =
				minimalConfigurationBuilder
						.grantType("some-grant-type")
						.claims((claims) -> claims.remove(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED))
						.build();
		assertThat(configuration.getGrantTypes()).isNull();
	}

	@Test
	public void claimsWhenAddingAClaimThenIsPresent() {
		OidcProviderConfiguration configuration =
				minimalConfigurationBuilder
						.claims((claims) -> claims.put(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, "authorization_code"))
						.build();
		assertThat(configuration.getGrantTypes()).containsExactly("authorization_code");
	}

	private static URL url(String urlString) {
		try {
			return new URL(urlString);
		} catch (MalformedURLException e) {
			throw new IllegalArgumentException("urlString must be a valid URL and valid URI");
		}
	}
}
