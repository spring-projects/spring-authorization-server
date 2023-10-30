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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

/**
 * Tests for {@link OAuth2AccessTokenResponseAuthenticationSuccessHandler}.
 *
 * @author Dmitriy Dubson
 */
public class OAuth2AccessTokenResponseAuthenticationSuccessHandlerTests {
	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();

	private final OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
			this.registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.registeredClient.getClientSecret());

	private final OAuth2AccessTokenResponseAuthenticationSuccessHandler authenticationSuccessHandler = new OAuth2AccessTokenResponseAuthenticationSuccessHandler();

	@Test
	public void setAccessTokenResponseCustomizerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authenticationSuccessHandler.setAccessTokenResponseCustomizer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("accessTokenResponseCustomizer cannot be null");
		// @formatter:on
	}

	@Test
	public void onAuthenticationSuccessWhenProvidedRequestResponseAndAuthThenWritesAccessTokenToHttpResponse() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		OAuth2Authorization testAuthorization = TestOAuth2Authorizations.authorization(this.registeredClient).build();
		Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");
		Authentication authentication = new OAuth2AccessTokenAuthenticationToken(this.registeredClient, clientPrincipal,
				testAuthorization.getAccessToken().getToken(), testAuthorization.getRefreshToken().getToken(),
				additionalParameters);

		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getIssuedAt()).isCloseTo(issuedAt, within(2, ChronoUnit.SECONDS));
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isCloseTo(expiresAt, within(2, ChronoUnit.SECONDS));
		assertThat(accessTokenResponse.getRefreshToken()).isNotNull();
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo("refresh-token");
		assertThat(accessTokenResponse.getAdditionalParameters()).containsExactlyInAnyOrderEntriesOf(
				Map.of("param1", "value1")
		);
	}

	@Test
	public void onAuthenticationSuccessWhenAuthenticationIsNotInstanceOfOAuth2AccessTokenAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		assertThatThrownBy(() ->
				this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, Set.of(), Map.of())))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
	}

	@Test
	public void onAuthenticationSuccessWhenAccessTokenResponseIsCustomizedViaAccessTokenResponseCustomizerThenResponseHasCustomizedFields() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		OAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
		OAuth2Authorization testAuthorization = TestOAuth2Authorizations.authorization(this.registeredClient).build();
		authorizationService.save(testAuthorization);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		OAuth2AccessToken accessToken = testAuthorization.getAccessToken().getToken();
		OAuth2RefreshToken refreshToken = testAuthorization.getRefreshToken().getToken();
		Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");
		Authentication authentication = new OAuth2AccessTokenAuthenticationToken(this.registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);

		Consumer<OAuth2AccessTokenAuthenticationContext> accessTokenResponseCustomizer = (OAuth2AccessTokenAuthenticationContext authenticationContext) -> {
			OAuth2AccessTokenAuthenticationToken authenticationToken = authenticationContext.getAuthentication();
			OAuth2AccessTokenResponse.Builder accessTokenResponse = authenticationContext.getAccessTokenResponse();
			OAuth2Authorization authorization = authorizationService.findByToken(
					authenticationToken.getAccessToken().getTokenValue(),
					OAuth2TokenType.ACCESS_TOKEN
			);
			Map<String, Object> customParams = Map.of(
					"authorization_id", authorization.getId(),
					"registered_client_id", authorization.getRegisteredClientId()
			);
			Map<String, Object> allParams = new HashMap<>(authenticationToken.getAdditionalParameters());
			allParams.putAll(customParams);
			accessTokenResponse.additionalParameters(allParams);
		};

		this.authenticationSuccessHandler.setAccessTokenResponseCustomizer(accessTokenResponseCustomizer);
		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getIssuedAt()).isCloseTo(issuedAt, within(2, ChronoUnit.SECONDS));
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isCloseTo(expiresAt, within(2, ChronoUnit.SECONDS));
		assertThat(accessTokenResponse.getRefreshToken()).isNotNull();
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo("refresh-token");
		assertThat(accessTokenResponse.getAdditionalParameters()).containsExactlyInAnyOrderEntriesOf(
				Map.of("param1", "value1", "authorization_id", "id", "registered_client_id", "registration-1")
		);
	}

	private OAuth2AccessTokenResponse readAccessTokenResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
		return this.accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

}
