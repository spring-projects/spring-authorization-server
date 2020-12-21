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
package org.springframework.security.oauth2.core.oidc.http.converter;

import org.junit.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Ovidiu Popa
 * @since 0.1.1
 */
public class OidcClientRegistrationHttpMessageConverterTest {
	private final OidcClientRegistrationHttpMessageConverter messageConverter =
			new OidcClientRegistrationHttpMessageConverter();

	@Test
	public void supportsWhenOidcClientRegistrationThenTrue() {
		assertThat(this.messageConverter.supports(OidcClientRegistration.class)).isTrue();
	}

	@Test
	public void setClientRegistrationReadConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.messageConverter.setClientRegistrationConverter(null))
				.withMessageContaining("clientRegistrationConverter cannot be null");
	}

	@Test
	public void setClientRegistrationWriteConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.messageConverter.setClientRegistrationParametersConverter(null))
				.withMessageContaining("clientRegistrationParametersConverter cannot be null");
	}

	@Test
	public void readInternalWhenRequiredParametersThenSuccess() {
		// @formatter:off
		String clientRegistrationResponse = "{\n"
				+ "		\"redirect_uris\": [\n"
				+ "			\"https://client.example.org/callback\"\n"
				+ "		]\n"
				+ "}\n";
		// @formatter:on

		MockClientHttpResponse response = new MockClientHttpResponse(clientRegistrationResponse.getBytes(), HttpStatus.OK);
		OidcClientRegistration clientRegistration = this.messageConverter
				.readInternal(OidcClientRegistration.class, response);

		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("https://client.example.org/callback");
		assertThat(clientRegistration.getGrantTypes())
				.containsOnly(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue()
				);
		assertThat(clientRegistration.getResponseTypes())
				.contains(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistration.getScope())
				.isNull();
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.BASIC.getValue());
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() {
		// @formatter:off
		String clientRegistrationResponse = "{\n"
				+"		\"redirect_uris\": [\n"
				+ "			\"https://client.example.org/callback\"\n"
				+ "		],\n"
				+"		\"grant_types\": [\n"
				+"			\"client_credentials\",\n"
				+"			\"authorization_code\"\n"
				+"		],\n"
				+"		\"response_types\":[\n"
				+"			\"code\"\n"
				+"		],\n"
				+"		\"client_name\": \"My Example\",\n"
				+"		\"scope\": \"read write\",\n"
				+"		\"token_endpoint_auth_method\": \"basic\"\n"
				+"}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(clientRegistrationResponse.getBytes(), HttpStatus.OK);

		OidcClientRegistration clientRegistration = this.messageConverter
				.readInternal(OidcClientRegistration.class, response);
		assertThat(clientRegistration.getRedirectUris())
				.containsOnly("https://client.example.org/callback");
		assertThat(clientRegistration.getGrantTypes())
				.contains(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()
				);
		assertThat(clientRegistration.getResponseTypes())
				.contains(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistration.getScope())
				.isEqualTo("read write");
		assertThat(clientRegistration.getTokenEndpointAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.BASIC.getValue());
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setClientRegistrationConverter(source -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OidcClientRegistration.class, response))
				.withMessageContaining("An error occurred reading the OpenID Client Registration Request")
				.withMessageContaining(errorMessage);
	}

	@Test
	public void readInternalWhenInvalidClientRegistrationThenThrowException() {
		String clientRegistrationResponse = "{ \"redirect_uris\": null }";
		MockClientHttpResponse response = new MockClientHttpResponse(clientRegistrationResponse.getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OidcClientRegistration.class, response))
				.withMessageContaining("An error occurred reading the OpenID Client Registration Request")
				.withMessageContaining("redirect_uris cannot be null");
	}

	@Test
	public void writeInternalWhenClientRegistrationThenSuccess() {
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.redirectUri("http://client.example.com/callback")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.scope("test read")
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.BASIC.getValue())
				.build();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(clientRegistration, outputMessage);
		String clientRegistrationResponse = outputMessage.getBodyAsString();
		assertThat(clientRegistrationResponse).contains("\"redirect_uris\":[\"http://client.example.com/callback\"]");
		assertThat(clientRegistrationResponse).contains("\"grant_types\":[\"authorization_code\",\"client_credentials\"]");
		assertThat(clientRegistrationResponse).contains("\"response_types\":[\"code\"]");
		assertThat(clientRegistrationResponse).contains("\"scope\":\"test read\"");
		assertThat(clientRegistrationResponse).contains("\"token_endpoint_auth_method\":\"basic\"");
	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowsException() {
		String errorMessage = "this is not a valid converter";
		Converter<OidcClientRegistration, Map<String, Object>> failingConverter =
				source -> {
					throw new RuntimeException(errorMessage);
				};
		this.messageConverter.setClientRegistrationParametersConverter(failingConverter);

		OidcClientRegistration clientRegistration =
				OidcClientRegistration.builder()
						.redirectUri("http://client.example.com")
						.build();

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatThrownBy(() -> this.messageConverter.writeInternal(clientRegistration, outputMessage))
				.isInstanceOf(HttpMessageNotWritableException.class)
				.hasMessageContaining("An error occurred writing the OpenID Client Registration response")
				.hasMessageContaining(errorMessage);
	}
}
