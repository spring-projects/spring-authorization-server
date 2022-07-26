/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2AuthorizationCodeRequestAuthenticationProvider}.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationCodeRequestAuthenticationProviderTests {
	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
	private RegisteredClientRepository registeredClientRepository;
	private OAuth2AuthorizationService authorizationService;
	private OAuth2AuthorizationConsentService authorizationConsentService;
	private OAuth2AuthorizationCodeRequestAuthenticationProvider authenticationProvider;
	private TestingAuthenticationToken principal;

	@Before
	public void setUp() {
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authorizationConsentService = mock(OAuth2AuthorizationConsentService.class);
		this.authenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService, this.authorizationConsentService);
		this.principal = new TestingAuthenticationToken("principalName", "password");
		this.principal.setAuthenticated(true);
		ProviderSettings providerSettings = ProviderSettings.builder().issuer("https://provider.com").build();
		ProviderContextHolder.setProviderContext(new ProviderContext(providerSettings, null));
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationProvider(
				null, this.authorizationService, this.authorizationConsentService))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationProvider(
				this.registeredClientRepository, null, this.authorizationConsentService))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationConsentServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationProvider(
				this.registeredClientRepository, this.authorizationService, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationConsentService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2AuthorizationCodeRequestAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeRequestAuthenticationToken.class)).isTrue();
	}

	@Test
	public void setAuthorizationCodeGeneratorWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setAuthorizationCodeGenerator(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationCodeGenerator cannot be null");
	}

	@Test
	public void setAuthenticationValidatorResolverWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setAuthenticationValidatorResolver(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authenticationValidatorResolver cannot be null");
	}

	@Test
	public void setAuthorizationConsentCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setAuthorizationConsentCustomizer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationConsentCustomizer cannot be null");
	}

	@Test
	public void authenticateWhenInvalidClientIdThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID, null)
				);
	}

	// gh-243
	@Test
	public void authenticateWhenInvalidRedirectUriHostThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri("https:///invalid")
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null)
				);
	}

	// gh-243
	@Test
	public void authenticateWhenInvalidRedirectUriFragmentThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri("https://example.com#fragment")
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null)
				);
	}

	// gh-243
	@Test
	public void authenticateWhenRedirectUriLocalhostThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri("https://localhost:5000")
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null)
				)
				.extracting(ex -> ((OAuth2AuthorizationCodeRequestAuthenticationException) ex).getError())
				.satisfies(error ->
						assertThat(error.getDescription()).isEqualTo("localhost is not allowed for the redirect_uri (https://localhost:5000). Use the IP literal (127.0.0.1) instead."));
	}

	@Test
	public void authenticateWhenUnregisteredRedirectUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri("https://invalid-example.com")
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null)
				);
	}

	// gh-243
	@Test
	public void authenticateWhenRedirectUriIPv4LoopbackAndDifferentPortThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.redirectUri("https://127.0.0.1:8080")
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri("https://127.0.0.1:5000")
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication, authenticationResult);
	}

	// gh-243
	@Test
	public void authenticateWhenRedirectUriIPv6LoopbackAndDifferentPortThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.redirectUri("https://[::1]:8080")
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri("https://[::1]:5000")
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication, authenticationResult);
	}

	@Test
	public void authenticateWhenMissingRedirectUriAndMultipleRegisteredThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUri("https://example2.com").build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri(null)
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null)
				);
	}

	@Test
	public void authenticateWhenAuthenticationRequestMissingRedirectUriThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		// redirect_uri is REQUIRED for OpenID Connect requests
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scope(OidcScopes.OPENID)
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.redirectUri(null)
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI, null)
				);
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRequestCodeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantTypes(Set::clear)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID, authentication.getRedirectUri())
				);
	}

	@Test
	public void authenticateWhenInvalidScopeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.scopes(Collections.singleton("invalid-scope"))
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE, authentication.getRedirectUri())
				);
	}

	@Test
	public void authenticateWhenPkceRequiredAndMissingCodeChallengeThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(ClientSettings.builder().requireProofKey(true).build())
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, authentication.getRedirectUri())
				);
	}

	@Test
	public void authenticateWhenPkceUnsupportedCodeChallengeMethodThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "unsupported");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.additionalParameters(additionalParameters)
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, authentication.getRedirectUri())
				);
	}

	// gh-770
	@Test
	public void authenticateWhenPkceMissingCodeChallengeMethodThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.additionalParameters(additionalParameters)
						.build();
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, authentication.getRedirectUri())
				);
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenReturnAuthorizationCodeRequest() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		this.principal.setAuthenticated(false);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertThat(authenticationResult).isSameAs(authentication);
		assertThat(authenticationResult.isAuthenticated()).isFalse();
	}

	@Test
	public void authenticateWhenRequireAuthorizationConsentThenReturnAuthorizationConsent() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo(authentication.getAuthorizationUri());
		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(authentication.getRedirectUri());
		assertThat(authorizationRequest.getScopes()).isEqualTo(authentication.getScopes());
		assertThat(authorizationRequest.getState()).isEqualTo(authentication.getState());
		assertThat(authorizationRequest.getAdditionalParameters()).isEqualTo(authentication.getAdditionalParameters());

		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName())).isEqualTo(this.principal);
		String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
		assertThat(state).isNotNull();
		assertThat(state).isNotEqualTo(authentication.getState());

		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.principal);
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authenticationResult.getScopes()).isEmpty();
		assertThat(authenticationResult.getState()).isEqualTo(state);
		assertThat(authenticationResult.isConsentRequired()).isTrue();
		assertThat(authenticationResult.getAuthorizationCode()).isNull();
		assertThat(authenticationResult.isAuthenticated()).isTrue();
	}

	@Test
	public void authenticateWhenRequireAuthorizationConsentAndOnlyOpenidScopeRequestedThenAuthorizationConsentNotRequired() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.scopes(scopes -> {
					scopes.clear();
					scopes.add(OidcScopes.OPENID);
				})
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication, authenticationResult);
	}

	@Test
	public void authenticateWhenRequireAuthorizationConsentAndAllPreviouslyApprovedThenAuthorizationConsentNotRequired() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2AuthorizationConsent.Builder builder =
				OAuth2AuthorizationConsent.withId(registeredClient.getId(), this.principal.getName());
		registeredClient.getScopes().forEach(builder::scope);
		OAuth2AuthorizationConsent previousAuthorizationConsent = builder.build();
		when(this.authorizationConsentService.findById(eq(registeredClient.getId()), eq(this.principal.getName())))
				.thenReturn(previousAuthorizationConsent);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication, authenticationResult);
	}

	@Test
	public void authenticateWhenAuthorizationCodeRequestValidThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.additionalParameters(additionalParameters)
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication, authenticationResult);
	}

	@Test
	public void authenticateWhenAuthorizationCodeNotGeneratedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		@SuppressWarnings("unchecked")
		OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = mock(OAuth2TokenGenerator.class);
		this.authenticationProvider.setAuthorizationCodeGenerator(authorizationCodeGenerator);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthorizationCodeRequestAuthenticationException) ex).getError())
				.satisfies(error -> {
					assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
					assertThat(error.getDescription()).contains("The token generator failed to generate the authorization code.");
				});
	}

	@Test
	public void authenticateWhenCustomAuthenticationValidatorResolverThenUsed() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		@SuppressWarnings("unchecked")
		Function<String, OAuth2AuthenticationValidator> authenticationValidatorResolver = mock(Function.class);
		this.authenticationProvider.setAuthenticationValidatorResolver(authenticationValidatorResolver);

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationCodeRequestAuthentication(registeredClient, this.principal)
						.build();

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationCodeRequestWithAuthorizationCodeResult(registeredClient, authentication, authenticationResult);

		ArgumentCaptor<String> parameterNameCaptor = ArgumentCaptor.forClass(String.class);
		verify(authenticationValidatorResolver, times(2)).apply(parameterNameCaptor.capture());
		assertThat(parameterNameCaptor.getAllValues()).containsExactly(
				OAuth2ParameterNames.REDIRECT_URI, OAuth2ParameterNames.SCOPE);
	}

	private void assertAuthorizationCodeRequestWithAuthorizationCodeResult(
			RegisteredClient registeredClient,
			OAuth2AuthorizationCodeRequestAuthenticationToken authentication,
			OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult) {

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo(authentication.getAuthorizationUri());
		assertThat(authorizationRequest.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(authentication.getRedirectUri());
		assertThat(authorizationRequest.getScopes()).isEqualTo(authentication.getScopes());
		assertThat(authorizationRequest.getState()).isEqualTo(authentication.getState());
		assertThat(authorizationRequest.getAdditionalParameters()).isEqualTo(authentication.getAdditionalParameters());

		assertThat(authorization.getRegisteredClientId()).isEqualTo(registeredClient.getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName())).isEqualTo(this.principal);

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
		Set<String> authorizedScopes = authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);

		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.principal);
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authenticationResult.getRedirectUri()).isEqualTo(authorizationRequest.getRedirectUri());
		assertThat(authenticationResult.getScopes()).isEqualTo(authorizedScopes);
		assertThat(authenticationResult.getState()).isEqualTo(authorizationRequest.getState());
		assertThat(authenticationResult.getAuthorizationCode()).isEqualTo(authorizationCode.getToken());
		assertThat(authenticationResult.isAuthenticated()).isTrue();
	}

	@Test
	public void authenticateWhenConsentRequestInvalidStateThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE, null)
				);
	}

	@Test
	public void authenticateWhenConsentRequestPrincipalNotAuthenticatedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);
		this.principal.setAuthenticated(false);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE, null)
				);
	}

	@Test
	public void authenticateWhenConsentRequestInvalidPrincipalThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName().concat("-other"))
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE, null)
				);
	}

	@Test
	public void authenticateWhenConsentRequestInvalidClientIdThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);
		RegisteredClient otherRegisteredClient = TestRegisteredClients.registeredClient2()
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(otherRegisteredClient, this.principal)
						.state("state")
						.build();

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID, null)
				);
	}

	@Test
	public void authenticateWhenConsentRequestDoesNotMatchClientThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		RegisteredClient otherRegisteredClient = TestRegisteredClients.registeredClient2()
				.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(otherRegisteredClient)
				.principalName(this.principal.getName())
				.build();
		when(this.authorizationService.findByToken(eq("state"), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.state("state")
						.build();

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID, null)
				);
	}

	@Test
	public void authenticateWhenConsentRequestScopeNotRequestedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = new HashSet<>(authorizationRequest.getScopes());
		authorizedScopes.add("scope-not-requested");
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.scopes(authorizedScopes)
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE, authorizationRequest.getRedirectUri())
				);
	}

	@Test
	public void authenticateWhenConsentRequestNotApprovedThenThrowOAuth2AuthorizationCodeRequestAuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.scopes(new HashSet<>())	// No scopes approved
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getRedirectUri())
				);

		verify(this.authorizationService).remove(eq(authorization));
	}

	@Test
	public void authenticateWhenConsentRequestApproveAllThenReturnAuthorizationCode() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = authorizationRequest.getScopes();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.scopes(authorizedScopes)		// Approve all scopes
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationConsentRequestWithAuthorizationCodeResult(registeredClient, authorization, authenticationResult);
	}

	@Test
	public void authenticateWhenCustomAuthorizationConsentCustomizerThenUsed() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = authorizationRequest.getScopes();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.scopes(authorizedScopes)		// Approve all scopes
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);

		@SuppressWarnings("unchecked")
		Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer = mock(Consumer.class);
		this.authenticationProvider.setAuthorizationConsentCustomizer(authorizationConsentCustomizer);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		assertAuthorizationConsentRequestWithAuthorizationCodeResult(registeredClient, authorization, authenticationResult);

		ArgumentCaptor<OAuth2AuthorizationConsentAuthenticationContext> authenticationContextCaptor =
				ArgumentCaptor.forClass(OAuth2AuthorizationConsentAuthenticationContext.class);
		verify(authorizationConsentCustomizer).accept(authenticationContextCaptor.capture());

		OAuth2AuthorizationConsentAuthenticationContext authenticationContext = authenticationContextCaptor.getValue();
		assertThat(authenticationContext.<Authentication>getAuthentication()).isEqualTo(authentication);
		assertThat(authenticationContext.getAuthorizationConsent()).isNotNull();
		assertThat(authenticationContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationContext.getAuthorization()).isEqualTo(authorization);
		assertThat(authenticationContext.getAuthorizationRequest()).isEqualTo(authorizationRequest);
	}

	private void assertAuthorizationConsentRequestWithAuthorizationCodeResult(
			RegisteredClient registeredClient,
			OAuth2Authorization authorization,
			OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult) {
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> authorizedScopes = authorizationRequest.getScopes();

		ArgumentCaptor<OAuth2AuthorizationConsent> authorizationConsentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationConsent.class);
		verify(this.authorizationConsentService).save(authorizationConsentCaptor.capture());
		OAuth2AuthorizationConsent authorizationConsent = authorizationConsentCaptor.getValue();

		assertThat(authorizationConsent.getRegisteredClientId()).isEqualTo(authorization.getRegisteredClientId());
		assertThat(authorizationConsent.getPrincipalName()).isEqualTo(authorization.getPrincipalName());
		assertThat(authorizationConsent.getAuthorities()).hasSize(authorizedScopes.size());
		assertThat(authorizationConsent.getScopes()).containsExactlyInAnyOrderElementsOf(authorizedScopes);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(updatedAuthorization.getRegisteredClientId()).isEqualTo(authorization.getRegisteredClientId());
		assertThat(updatedAuthorization.getPrincipalName()).isEqualTo(authorization.getPrincipalName());
		assertThat(updatedAuthorization.getAuthorizationGrantType()).isEqualTo(authorization.getAuthorizationGrantType());
		assertThat(updatedAuthorization.<Authentication>getAttribute(Principal.class.getName()))
				.isEqualTo(authorization.<Authentication>getAttribute(Principal.class.getName()));
		assertThat(updatedAuthorization.<OAuth2AuthorizationRequest>getAttribute(OAuth2AuthorizationRequest.class.getName()))
				.isEqualTo(authorizationRequest);
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = updatedAuthorization.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCode).isNotNull();
		assertThat(updatedAuthorization.<String>getAttribute(OAuth2ParameterNames.STATE)).isNull();
		assertThat(updatedAuthorization.<Set<String>>getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME))
				.isEqualTo(authorizedScopes);

		assertThat(authenticationResult.getClientId()).isEqualTo(registeredClient.getClientId());
		assertThat(authenticationResult.getPrincipal()).isEqualTo(this.principal);
		assertThat(authenticationResult.getAuthorizationUri()).isEqualTo(authorizationRequest.getAuthorizationUri());
		assertThat(authenticationResult.getRedirectUri()).isEqualTo(authorizationRequest.getRedirectUri());
		assertThat(authenticationResult.getScopes()).isEqualTo(authorizedScopes);
		assertThat(authenticationResult.getState()).isEqualTo(authorizationRequest.getState());
		assertThat(authenticationResult.getAuthorizationCode()).isEqualTo(authorizationCode.getToken());
		assertThat(authenticationResult.isAuthenticated()).isTrue();
	}

	@Test
	public void authenticateWhenConsentRequestApproveNoneAndRevokePreviouslyApprovedThenAuthorizationConsentRemoved() {
		String previouslyApprovedScope = "message.read";
		String requestedScope = "message.write";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add(previouslyApprovedScope);
					scopes.add(requestedScope);
				})
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.scopes(new HashSet<>())	// No scopes approved
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);
		OAuth2AuthorizationConsent previousAuthorizationConsent =
				OAuth2AuthorizationConsent.withId(authorization.getRegisteredClientId(), authorization.getPrincipalName())
						.scope(previouslyApprovedScope)
						.build();
		when(this.authorizationConsentService.findById(eq(authorization.getRegisteredClientId()), eq(authorization.getPrincipalName())))
				.thenReturn(previousAuthorizationConsent);

		// Revoke all (including previously approved)
		this.authenticationProvider.setAuthorizationConsentCustomizer((authorizationConsentContext) ->
				authorizationConsentContext.getAuthorizationConsent().authorities(Set::clear));

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthorizationCodeRequestAuthenticationException.class)
				.satisfies(ex ->
						assertAuthenticationException((OAuth2AuthorizationCodeRequestAuthenticationException) ex,
								OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID, authorizationRequest.getRedirectUri())
				);

		verify(this.authorizationConsentService).remove(eq(previousAuthorizationConsent));
		verify(this.authorizationService).remove(eq(authorization));
	}

	@Test
	public void authenticateWhenConsentRequestApproveSomeAndPreviouslyApprovedThenAuthorizationConsentUpdated() {
		String previouslyApprovedScope = "message.read";
		String requestedScope = "message.write";
		String otherPreviouslyApprovedScope = "other.scope";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add(previouslyApprovedScope);
					scopes.add(requestedScope);
				})
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> requestedScopes = authorizationRequest.getScopes();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.scopes(requestedScopes)
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);
		OAuth2AuthorizationConsent previousAuthorizationConsent =
				OAuth2AuthorizationConsent.withId(authorization.getRegisteredClientId(), authorization.getPrincipalName())
						.scope(previouslyApprovedScope)
						.scope(otherPreviouslyApprovedScope)
						.build();
		when(this.authorizationConsentService.findById(eq(authorization.getRegisteredClientId()), eq(authorization.getPrincipalName())))
				.thenReturn(previousAuthorizationConsent);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		ArgumentCaptor<OAuth2AuthorizationConsent> authorizationConsentCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationConsent.class);
		verify(this.authorizationConsentService).save(authorizationConsentCaptor.capture());
		OAuth2AuthorizationConsent updatedAuthorizationConsent = authorizationConsentCaptor.getValue();

		assertThat(updatedAuthorizationConsent.getRegisteredClientId()).isEqualTo(previousAuthorizationConsent.getRegisteredClientId());
		assertThat(updatedAuthorizationConsent.getPrincipalName()).isEqualTo(previousAuthorizationConsent.getPrincipalName());
		assertThat(updatedAuthorizationConsent.getScopes()).containsExactlyInAnyOrder(
				previouslyApprovedScope, otherPreviouslyApprovedScope, requestedScope);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(updatedAuthorization.<Set<String>>getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME))
				.isEqualTo(requestedScopes);

		assertThat(authenticationResult.getScopes()).isEqualTo(requestedScopes);
	}

	@Test
	public void authenticateWhenConsentRequestApproveNoneAndPreviouslyApprovedThenAuthorizationConsentNotUpdated() {
		String previouslyApprovedScope = "message.read";
		String requestedScope = "message.write";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.scopes(scopes -> {
					scopes.clear();
					scopes.add(previouslyApprovedScope);
					scopes.add(requestedScope);
				})
				.build();
		when(this.registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(this.principal.getName())
				.build();
		OAuth2AuthorizationCodeRequestAuthenticationToken authentication =
				authorizationConsentRequestAuthentication(registeredClient, this.principal)
						.scopes(new HashSet<>())	// No scopes approved
						.build();
		when(this.authorizationService.findByToken(eq(authentication.getState()), eq(STATE_TOKEN_TYPE)))
				.thenReturn(authorization);
		OAuth2AuthorizationConsent previousAuthorizationConsent =
				OAuth2AuthorizationConsent.withId(authorization.getRegisteredClientId(), authorization.getPrincipalName())
						.scope(previouslyApprovedScope)
						.build();
		when(this.authorizationConsentService.findById(eq(authorization.getRegisteredClientId()), eq(authorization.getPrincipalName())))
				.thenReturn(previousAuthorizationConsent);

		OAuth2AuthorizationCodeRequestAuthenticationToken authenticationResult =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationProvider.authenticate(authentication);

		verify(this.authorizationConsentService, never()).save(any());
		assertThat(authenticationResult.getScopes()).isEqualTo(Collections.singleton(previouslyApprovedScope));
	}

	private static void assertAuthenticationException(OAuth2AuthorizationCodeRequestAuthenticationException authenticationException,
			String errorCode, String parameterName, String redirectUri) {

		OAuth2Error error = authenticationException.getError();
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
		assertThat(error.getDescription()).contains(parameterName);

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				authenticationException.getAuthorizationCodeRequestAuthentication();
		assertThat(authorizationCodeRequestAuthentication.getRedirectUri()).isEqualTo(redirectUri);

		// gh-595
		if (OAuth2ErrorCodes.ACCESS_DENIED.equals(errorCode)) {
			assertThat(authorizationCodeRequestAuthentication.isConsent()).isFalse();
			assertThat(authorizationCodeRequestAuthentication.isConsentRequired()).isFalse();
		}
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken.Builder authorizationCodeRequestAuthentication(
			RegisteredClient registeredClient, Authentication principal) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri("https://provider.com/oauth2/authorize")
				.redirectUri(registeredClient.getRedirectUris().iterator().next())
				.scopes(registeredClient.getScopes())
				.state("state");
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken.Builder authorizationConsentRequestAuthentication(
			RegisteredClient registeredClient, Authentication principal) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri("https://provider.com/oauth2/authorize")
				.scopes(registeredClient.getScopes())
				.state("state")
				.consent(true);
	}

}
