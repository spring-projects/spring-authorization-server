/*
 * Copyright 2020-2026 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OidcClientRegistrationAuthenticationValidator}.
 *
 * @author addcontent
 */
class OidcClientRegistrationAuthenticationValidatorTests {

	private static final Authentication PRINCIPAL = new TestingAuthenticationToken("principal", "credentials");

	@Test
	void validateWhenRedirectUriValidThenNoException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatCode(
				() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context))
			.doesNotThrowAnyException();
	}

	@Test
	void validateWhenRedirectUriHasFragmentThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback#fragment")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(
					() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
	}

	@Test
	void validateWhenRedirectUriHasNoSchemeThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("//client.example.com/callback")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(
					() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
	}

	@Test
	void validateWhenRedirectUriHasJavascriptSchemeThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("javascript:alert(document.cookie)")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(
					() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
	}

	@Test
	void validateWhenRedirectUriValidOnlyThenNoException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatCode(
				() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR.accept(context))
			.doesNotThrowAnyException();
	}

	@Test
	void validateWhenPostLogoutRedirectUriHasFragmentThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.postLogoutRedirectUri("https://client.example.com/logout#fragment")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR
				.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo("invalid_client_metadata");
	}

	@Test
	void validateWhenPostLogoutRedirectUriHasUnsafeSchemeThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.postLogoutRedirectUri("data:text/html,<b>content</b>")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR
				.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo("invalid_client_metadata");
	}

	@Test
	void validateWhenJwksUriHttpsThenNoException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.jwkSetUrl("https://client.example.com/jwks")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatCode(
				() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR.accept(context))
			.doesNotThrowAnyException();
	}

	@Test
	void validateWhenJwksUriHttpThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.jwkSetUrl("http://169.254.169.254/keys")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(
					() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo("invalid_client_metadata");
	}

	@Test
	void validateWhenJwksUriNullThenNoException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatCode(
				() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_JWK_SET_URI_VALIDATOR.accept(context))
			.doesNotThrowAnyException();
	}

	@Test
	void validateWhenScopeEmptyThenNoException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatCode(() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR.accept(context))
			.doesNotThrowAnyException();
	}

	@Test
	void validateWhenScopeNonEmptyThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.scope("read")
			.scope("write")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> OidcClientRegistrationAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	void validateWhenSimpleScopeValidatorAndScopeNonEmptyThenNoException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/callback")
			.scope("read")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatCode(() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_SCOPE_VALIDATOR.accept(context))
			.doesNotThrowAnyException();
	}

	@Test
	void validateWhenSimpleRedirectUriAndJavascriptSchemeThenNoException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("javascript:alert(document.cookie)")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatCode(
				() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(context))
			.doesNotThrowAnyException();
	}

	@Test
	void validateWhenSimpleRedirectUriAndFragmentThenException() {
		OidcClientRegistration registration = OidcClientRegistration.builder()
			.redirectUri("https://client.example.com/cb#fragment")
			.build();
		OidcClientRegistrationAuthenticationContext context = contextFor(registration);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(
					() -> OidcClientRegistrationAuthenticationValidator.SIMPLE_REDIRECT_URI_VALIDATOR.accept(context))
			.extracting((ex) -> ex.getError().getErrorCode())
			.isEqualTo(OAuth2ErrorCodes.INVALID_REDIRECT_URI);
	}

	private static OidcClientRegistrationAuthenticationContext contextFor(OidcClientRegistration registration) {
		OidcClientRegistrationAuthenticationToken token = new OidcClientRegistrationAuthenticationToken(PRINCIPAL,
				registration);
		return OidcClientRegistrationAuthenticationContext.with(token).build();
	}

}
