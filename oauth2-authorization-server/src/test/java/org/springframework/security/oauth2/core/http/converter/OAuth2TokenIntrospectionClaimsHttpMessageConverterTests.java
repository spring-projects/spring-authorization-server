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
package org.springframework.security.oauth2.core.http.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimAccessor.ACTIVE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.USERNAME;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.JTI;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.NBF;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

import org.assertj.core.api.Condition;
import org.junit.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.http.converter.OAuth2TokenIntrospectionClaimsHttpMessageConverter;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaims;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

/**
 * Tests for {@link OAuth2TokenIntrospectionClaimsHttpMessageConverter}
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionClaimsHttpMessageConverterTests {
	private final OAuth2TokenIntrospectionClaimsHttpMessageConverter messageConverter = new OAuth2TokenIntrospectionClaimsHttpMessageConverter();

	@Test
	public void supportsWhenOidcProviderConfigurationThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2TokenIntrospectionClaims.class)).isTrue();
	}

	@Test
	public void setProviderConfigurationParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.messageConverter.setTokenIntrospectionResponseParametersConverter(null));
	}

	@Test
	public void setProviderConfigurationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.messageConverter.setTokenIntrospectionResponseConverter(null));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void readInternalWhenValidParametersThenSuccess() throws Exception {
		// @formatter:off
		String tokenIntrospectionResponseBody = "{\n"
				+ "		\"active\": true,\n"
				+ "		\"iss\": \"https://example.com/issuer1\",\n"
				+ "		\"scope\": \"scope1 Scope2\",\n"
				+ "		\"client_id\": \"clientId1\",\n"
				+ "		\"token_type\": \"Bearer\",\n"
				+ "		\"username\": \"username1\",\n"
				+ "		\"aud\": [\"audience1\", \"audience2\"],\n"
				+ "		\"exp\": 1607637467,\n"
				+ "		\"iat\": 1607633867,\n"
				+ "		\"nbf\": 1607633867,\n"
				+ "		\"sub\": \"subject1\",\n"
				+ "		\"jti\": \"jwtId1\"\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(
				tokenIntrospectionResponseBody.getBytes(), HttpStatus.OK);
		OAuth2TokenIntrospectionClaims tokenIntrospectionResponse = this.messageConverter
				.readInternal(OAuth2TokenIntrospectionClaims.class, response);
		Map<String, Object> responseParameters = tokenIntrospectionResponse.getClaims();
		Condition<Object> collectionContainsCondition = new Condition<>(
				collection -> Collection.class.isAssignableFrom(collection.getClass())
						&& ((Collection<String>) collection).contains("audience1")
						&& ((Collection<String>) collection).contains("audience2"),
				"collection contains entries");

		// @formatter:off
		assertThat(responseParameters)
			.containsEntry(ACTIVE, true)
			.containsEntry(SCOPE, "scope1 Scope2")
			.containsEntry(CLIENT_ID, "clientId1")
			.containsEntry(TOKEN_TYPE, "Bearer")
			.containsEntry(USERNAME, "username1")
			.hasEntrySatisfying(AUD, collectionContainsCondition)
			.containsEntry(EXP, 1607637467L)
			.containsEntry(IAT, 1607633867L)
			.containsEntry(NBF, 1607633867L)
			.containsEntry(ISS, "https://example.com/issuer1")
			.containsEntry(JTI, "jwtId1")
			.containsEntry(SUB, "subject1");
		// @formatter:on
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setTokenIntrospectionResponseConverter(source -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OAuth2TokenIntrospectionClaims.class, response))
				.withMessageContaining("An error occurred reading the Token Introspection Response")
				.withMessageContaining(errorMessage);
	}

	@Test
	public void writeInternalWhenTokenIntrospectionResponseThenSuccess() {
		// @formatter:off
		OAuth2TokenIntrospectionClaims providerConfiguration = OAuth2TokenIntrospectionClaims.builder(true)
				.issuer("https://example.com/issuer1")
				.scope("scope1 Scope2")
				.clientId("clientId1")
				.tokenType(TokenType.BEARER)
				.username("username1")
				.audience(Arrays.asList("audience1", "audience2"))
				.expirationTime(Instant.ofEpochSecond(1607637467))
				.issuedAt(Instant.ofEpochSecond(1607633867))
				.notBefore(Instant.ofEpochSecond(1607633867))
				.jwtId("jwtId1")
				.subject("subject1").build();
		// @formatter:on
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(providerConfiguration, outputMessage);

		String providerConfigurationResponse = outputMessage.getBodyAsString();
		// @formatter:off
		assertThat(providerConfigurationResponse)
			.contains("\"iss\":\"https://example.com/issuer1\"")
			.contains("\"active\":true")
			.contains("\"scope\":\"scope1 Scope2\"")
			.contains("\"client_id\":\"clientId1\"")
			.contains("\"token_type\":\"Bearer\"")
			.contains("\"username\":\"username1\"")
			.contains("\"aud\":[\"audience1\",\"audience2\"]")
			.contains("\"exp\":1607637467")
			.contains("\"iat\":1607633867")
			.contains("\"nbf\":1607633867")
			.contains("\"jti\":\"jwtId1\"")
			.contains("\"sub\":\"subject1\"");
		// @formatter:on
	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowsException() {
		String errorMessage = "this is not a valid converter";
		Converter<OAuth2TokenIntrospectionClaims, Map<String, Object>> failingConverter = source -> {
			throw new RuntimeException(errorMessage);
		};
		this.messageConverter.setTokenIntrospectionResponseParametersConverter(failingConverter);

		OAuth2TokenIntrospectionClaims providerConfiguration = OAuth2TokenIntrospectionClaims.builder(true).build();

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		assertThatThrownBy(() -> this.messageConverter.writeInternal(providerConfiguration, outputMessage))
				.isInstanceOf(HttpMessageNotWritableException.class)
				.hasMessageContaining("An error occurred writing the Token Introspection Response")
				.hasMessageContaining(errorMessage);
	}
}
