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
package org.springframework.security.oauth2.core.http.converter;


import org.junit.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationServerConfiguration;

import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2AuthorizationServerConfigurationHttpMessageConverter}
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationServerConfigurationHttpMessageConverterTests {
	private final OAuth2AuthorizationServerConfigurationHttpMessageConverter messageConverter = new OAuth2AuthorizationServerConfigurationHttpMessageConverter();

	@Test
	public void supportsWhenOAuth2AuthorizationServerConfigurationThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2AuthorizationServerConfiguration.class)).isTrue();
	}

	@Test
	public void setAuthorizationServerConfigurationParametersConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messageConverter.setAuthorizationServerConfigurationParametersConverter(null));
	}

	@Test
	public void setAuthorizationServerConfigurationConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messageConverter.setAuthorizationServerConfigurationConverter(null));
	}

	@Test
	public void readInternalWhenRequiredParametersThenSuccess() throws Exception {
		// @formatter:off
		String serverConfigurationResponse = "{\n"
				+ "		\"issuer\": \"https://example.com/issuer1\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/issuer1/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/issuer1/oauth2/token\",\n"
				+ "		\"jwks_uri\": \"https://example.com/issuer1/oauth2/jwks\",\n"
				+ "		\"response_types_supported\": [\"code\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(serverConfigurationResponse.getBytes(), HttpStatus.OK);
		OAuth2AuthorizationServerConfiguration serverConfiguration = this.messageConverter
				.readInternal(OAuth2AuthorizationServerConfiguration.class, response);

		assertThat(serverConfiguration.getIssuer()).isEqualTo(new URL("https://example.com/issuer1"));
		assertThat(serverConfiguration.getAuthorizationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/authorize"));
		assertThat(serverConfiguration.getTokenEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/token"));
		assertThat(serverConfiguration.getJwkSetUri()).isEqualTo(new URL("https://example.com/issuer1/oauth2/jwks"));
		assertThat(serverConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(serverConfiguration.getScopes()).isNull();
		assertThat(serverConfiguration.getGrantTypes()).isNull();
		assertThat(serverConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(serverConfiguration.getCodeChallengeMethods()).isNull();
		assertThat(serverConfiguration.getTokenRevocationEndpoint()).isNull();
		assertThat(serverConfiguration.getTokenRevocationEndpointAuthenticationMethods()).isNull();
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() throws Exception {
		// @formatter:off
		String serverConfigurationResponse = "{\n"
				+ "		\"issuer\": \"https://example.com/issuer1\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/issuer1/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/issuer1/oauth2/token\",\n"
				+ "		\"revocation_endpoint\": \"https://example.com/issuer1/oauth2/revoke\",\n"
				+ "		\"jwks_uri\": \"https://example.com/issuer1/oauth2/jwks\",\n"
				+ "		\"response_types_supported\": [\"code\"],\n"
				+ "		\"grant_types_supported\": [\"authorization_code\", \"client_credentials\"],\n"
				+ "		\"scopes_supported\": [\"openid\"],\n"
				+ "		\"token_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"revocation_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"code_challenge_methods_supported\": [\"plain\",\"S256\"],\n"
				+ "		\"custom_claim\": \"value\",\n"
				+ "		\"custom_collection_claim\": [\"value1\", \"value2\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(serverConfigurationResponse.getBytes(), HttpStatus.OK);
		OAuth2AuthorizationServerConfiguration serverConfiguration = this.messageConverter
				.readInternal(OAuth2AuthorizationServerConfiguration.class, response);

		assertThat(serverConfiguration.getClaims()).hasSize(13);
		assertThat(serverConfiguration.getIssuer()).isEqualTo(new URL("https://example.com/issuer1"));
		assertThat(serverConfiguration.getAuthorizationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/authorize"));
		assertThat(serverConfiguration.getTokenEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/token"));
		assertThat(serverConfiguration.getTokenRevocationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/revoke"));
		assertThat(serverConfiguration.getJwkSetUri()).isEqualTo(new URL("https://example.com/issuer1/oauth2/jwks"));
		assertThat(serverConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(serverConfiguration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "client_credentials");
		assertThat(serverConfiguration.getScopes()).containsExactly("openid");
		assertThat(serverConfiguration.getTokenEndpointAuthenticationMethods()).containsExactly("client_secret_basic");
		assertThat(serverConfiguration.getTokenRevocationEndpointAuthenticationMethods()).containsExactly("client_secret_basic");
		assertThat(serverConfiguration.getCodeChallengeMethods()).containsExactlyInAnyOrder("plain", "S256");
		assertThat(serverConfiguration.getClaimAsString("custom_claim")).isEqualTo("value");
		assertThat(serverConfiguration.getClaimAsStringList("custom_collection_claim")).containsExactlyInAnyOrder("value1", "value2");
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setAuthorizationServerConfigurationConverter(source -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OAuth2AuthorizationServerConfiguration.class, response))
				.withMessageContaining("An error occurred reading the OAuth 2.0 Authorization Server Configuration")
				.withMessageContaining(errorMessage);
	}

	@Test
	public void readInternalWhenInvalidOAuth2AuthorizationServerConfigurationThenThrowException() {
		String providerConfigurationResponse = "{ \"issuer\": null }";
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OAuth2AuthorizationServerConfiguration.class, response))
				.withMessageContaining("An error occurred reading the OAuth 2.0 Authorization Server Configuration")
				.withMessageContaining("issuer cannot be null");
	}

	@Test
	public void writeInternalWhenOAuth2AuthorizationServerConfigurationThenSuccess() {
		OAuth2AuthorizationServerConfiguration serverConfiguration =
				OAuth2AuthorizationServerConfiguration
						.builder()
						.issuer("https://example.com/issuer1")
						.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
						.tokenEndpoint("https://example.com/issuer1/oauth2/token")
						.tokenRevocationEndpoint("https://example.com/issuer1/oauth2/revoke")
						.jwkSetUri("https://example.com/issuer1/oauth2/jwks")
						.scope("openid")
						.responseType("code")
						.grantType("authorization_code")
						.grantType("client_credentials")
						.tokenEndpointAuthenticationMethod("client_secret_basic")
						.tokenRevocationEndpointAuthenticationMethod("client_secret_basic")
						.codeChallengeMethod("plain")
						.codeChallengeMethod("S256")
						.claim("custom_claim", "value")
						.claim("custom_collection_claim", Arrays.asList("value1", "value2"))
						.build();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(serverConfiguration, outputMessage);

		String serverConfigurationResponse = outputMessage.getBodyAsString();
		assertThat(serverConfigurationResponse).contains("\"issuer\":\"https://example.com/issuer1\"");
		assertThat(serverConfigurationResponse).contains("\"authorization_endpoint\":\"https://example.com/issuer1/oauth2/authorize\"");
		assertThat(serverConfigurationResponse).contains("\"token_endpoint\":\"https://example.com/issuer1/oauth2/token\"");
		assertThat(serverConfigurationResponse).contains("\"revocation_endpoint\":\"https://example.com/issuer1/oauth2/revoke\"");
		assertThat(serverConfigurationResponse).contains("\"jwks_uri\":\"https://example.com/issuer1/oauth2/jwks\"");
		assertThat(serverConfigurationResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(serverConfigurationResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(serverConfigurationResponse).contains("\"grant_types_supported\":[\"authorization_code\",\"client_credentials\"]");
		assertThat(serverConfigurationResponse).contains("\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(serverConfigurationResponse).contains("\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(serverConfigurationResponse).contains("\"code_challenge_methods_supported\":[\"plain\",\"S256\"]");
		assertThat(serverConfigurationResponse).contains("\"custom_claim\":\"value\"");
		assertThat(serverConfigurationResponse).contains("\"custom_collection_claim\":[\"value1\",\"value2\"]");

	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowsException() {
		String errorMessage = "this is not a valid converter";
		Converter<OAuth2AuthorizationServerConfiguration, Map<String, Object>> failingConverter =
				source -> {
					throw new RuntimeException(errorMessage);
				};
		this.messageConverter.setAuthorizationServerConfigurationParametersConverter(failingConverter);

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		OAuth2AuthorizationServerConfiguration serverConfiguration =
				OAuth2AuthorizationServerConfiguration
						.builder()
						.issuer("https://example.com/issuer1")
						.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
						.tokenEndpoint("https://example.com/issuer1/oauth2/token")
						.jwkSetUri("https://example.com/issuer1/oauth2/jwks")
						.responseType("code")
						.build();

		assertThatExceptionOfType(HttpMessageNotWritableException.class)
				.isThrownBy(() -> this.messageConverter.writeInternal(serverConfiguration, outputMessage))
				.withMessageContaining("An error occurred writing the OAuth 2.0 Authorization Server Configuration")
				.withMessageContaining(errorMessage);
	}
}
