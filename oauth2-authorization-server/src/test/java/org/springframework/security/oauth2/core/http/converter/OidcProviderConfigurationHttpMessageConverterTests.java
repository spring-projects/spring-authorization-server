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
import org.springframework.security.oauth2.core.oidc.OidcProviderConfiguration;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OidcProviderConfigurationHttpMessageConverter}
 *
 * @author Daniel Garnier-Moiroux
 */
public class OidcProviderConfigurationHttpMessageConverterTests {
	private final OidcProviderConfigurationHttpMessageConverter messageConverter = new OidcProviderConfigurationHttpMessageConverter();

	@Test
	public void supportsWhenOidcProviderConfigurationThenTrue() {
		assertThat(this.messageConverter.supports(OidcProviderConfiguration.class)).isTrue();
	}

	@Test
	public void setProviderConfigurationParametersConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messageConverter.setProviderConfigurationParametersConverter(null));
	}

	@Test
	public void setProviderConfigurationConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messageConverter.setProviderConfigurationConverter(null));
	}

	@Test
	public void readInternalWhenSuccessfulProviderConfigurationOnlyRequiredParametersThenReadOidcProviderConfiguration() throws Exception {
		// @formatter:off
		String providerConfigurationResponse = "{\n"
				+ "		\"issuer\": \"https://example.com/issuer1\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/issuer1/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/issuer1/oauth2/token\",\n"
				+ "		\"jwks_uri\": \"https://example.com/issuer1/oauth2/jwks\",\n"
				+ "		\"response_types_supported\": [\"code\"],\n"
				+ "		\"subject_types_supported\": [\"public\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(), HttpStatus.OK);
		OidcProviderConfiguration providerConfiguration = this.messageConverter
				.readInternal(OidcProviderConfiguration.class, response);

		assertThat(providerConfiguration.getIssuer()).isEqualTo(new URL("https://example.com/issuer1"));
		assertThat(providerConfiguration.getAuthorizationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/token"));
		assertThat(providerConfiguration.getJwksUri()).isEqualTo(new URL("https://example.com/issuer1/oauth2/jwks"));
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getScopes()).isNull();
		assertThat(providerConfiguration.getGrantTypes()).isNull();
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).isNull();
	}

	@Test
	public void readInternalWhenSuccessfulProviderConfigurationThenReadOidcProviderConfiguration() throws Exception {
		// @formatter:off
		String providerConfigurationResponse = "{\n"
				+ "		\"issuer\": \"https://example.com/issuer1\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/issuer1/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/issuer1/oauth2/token\",\n"
				+ "		\"jwks_uri\": \"https://example.com/issuer1/oauth2/jwks\",\n"
				+ "		\"scopes_supported\": [\"openid\"],\n"
				+ "		\"response_types_supported\": [\"code\"],\n"
				+ "		\"grant_types_supported\": [\"authorization_code\", \"client_credentials\"],\n"
				+ "		\"subject_types_supported\": [\"public\"],\n"
				+ "		\"token_endpoint_auth_methods_supported\": [\"basic\"],\n"
				+ "		\"custom_claim\": \"value\",\n"
				+ "		\"custom_collection_claim\": [\"value1\", \"value2\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(), HttpStatus.OK);
		OidcProviderConfiguration providerConfiguration = this.messageConverter
				.readInternal(OidcProviderConfiguration.class, response);

		assertThat(providerConfiguration.getIssuer()).isEqualTo(new URL("https://example.com/issuer1"));
		assertThat(providerConfiguration.getAuthorizationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/authorize"));
		assertThat(providerConfiguration.getTokenEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/token"));
		assertThat(providerConfiguration.getJwksUri()).isEqualTo(new URL("https://example.com/issuer1/oauth2/jwks"));
		assertThat(providerConfiguration.getScopes()).containsExactly("openid");
		assertThat(providerConfiguration.getResponseTypes()).containsExactly("code");
		assertThat(providerConfiguration.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "client_credentials");
		assertThat(providerConfiguration.getSubjectTypes()).containsExactly("public");
		assertThat(providerConfiguration.getTokenEndpointAuthenticationMethods()).containsExactly("basic");
		assertThat(providerConfiguration.getClaimAsString("custom_claim")).isEqualTo("value");
		assertThat(providerConfiguration.getClaimAsStringList("custom_collection_claim")).containsExactlyInAnyOrder("value1", "value2");
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setProviderConfigurationConverter(source -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OidcProviderConfiguration.class, response))
				.withMessageContaining("An error occurred reading the OpenID Provider Configuration")
				.withMessageContaining(errorMessage);
	}

	@Test
	public void readInternalWhenInvalidProviderConfigurationThenThrowException() {
		String providerConfigurationResponse = "{ \"issuer\": null }";
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OidcProviderConfiguration.class, response))
				.withMessageContaining("An error occurred reading the OpenID Provider Configuration")
				.withMessageContaining("issuer cannot be null");
	}

	@Test
	public void writeInternalWhenOidcProviderConfigurationThenWriteTokenResponse() throws Exception {
		OidcProviderConfiguration providerConfiguration =
				OidcProviderConfiguration.withClaims()
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
						.claim("custom_claim", "value")
						.claim("custom_collection_claim", Arrays.asList("value1", "value2"))
						.build();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(providerConfiguration, outputMessage);

		String providerConfigurationResponse = outputMessage.getBodyAsString();
		assertThat(providerConfigurationResponse).contains("\"issuer\":\"https://example.com/issuer1\"");
		assertThat(providerConfigurationResponse).contains("\"authorization_endpoint\":\"https://example.com/issuer1/oauth2/authorize\"");
		assertThat(providerConfigurationResponse).contains("\"token_endpoint\":\"https://example.com/issuer1/oauth2/token\"");
		assertThat(providerConfigurationResponse).contains("\"jwks_uri\":\"https://example.com/issuer1/oauth2/jwks\"");
		assertThat(providerConfigurationResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(providerConfigurationResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(providerConfigurationResponse).contains("\"grant_types_supported\":[\"authorization_code\",\"client_credentials\"]");
		assertThat(providerConfigurationResponse).contains("\"subject_types_supported\":[\"public\"]");
		assertThat(providerConfigurationResponse).contains("\"token_endpoint_auth_methods_supported\":[\"basic\"]");
		assertThat(providerConfigurationResponse).contains("\"custom_claim\":\"value\"");
		assertThat(providerConfigurationResponse).contains("\"custom_collection_claim\":[\"value1\",\"value2\"]");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void writeInternalWhenWriteFailsThenThrowsException() throws MalformedURLException {
		String errorMessage = "this is not a valid converter";
		Converter<OidcProviderConfiguration, Map<String, Object>> failingConverter =
				source -> {
					throw new RuntimeException(errorMessage);
				};
		this.messageConverter.setProviderConfigurationParametersConverter(failingConverter);

		OidcProviderConfiguration providerConfiguration =
				OidcProviderConfiguration.withClaims()
						.issuer("https://example.com")
						.authorizationEndpoint("https://example.com")
						.tokenEndpoint("https://example.com")
						.jwksUri("https://example.com")
						.responseType("code")
						.subjectType("public")
						.build();

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatThrownBy(() -> this.messageConverter.writeInternal(providerConfiguration, outputMessage))
				.isInstanceOf(HttpMessageNotWritableException.class)
				.hasMessageContaining("An error occurred writing the OpenID Provider Configuration")
				.hasMessageContaining(errorMessage);
	}
}
