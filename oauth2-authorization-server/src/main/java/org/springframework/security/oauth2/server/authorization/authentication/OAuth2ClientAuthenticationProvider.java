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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceCodeChallengeMethod2;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation used for authenticating an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @author Daniel Garnier-Moiroux
 * @since 0.0.1
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 */
public class OAuth2ClientAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OAuth2ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient();
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(
				clientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient();
		}

		boolean authenticatedCredentials = false;

		if (clientAuthentication.getCredentials() != null) {
			String clientSecret = clientAuthentication.getCredentials().toString();
			// TODO Use PasswordEncoder.matches()
			if (!registeredClient.getClientSecret().equals(clientSecret)) {
				throwInvalidClient();
			}
			authenticatedCredentials = true;
		}

		authenticatedCredentials = authenticatedCredentials ||
				authenticatePkceIfAvailable(clientAuthentication, registeredClient);
		if (!authenticatedCredentials) {
			throwInvalidClient();
		}

		return new OAuth2ClientAuthenticationToken(registeredClient);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private boolean authenticatePkceIfAvailable(OAuth2ClientAuthenticationToken clientAuthentication,
			RegisteredClient registeredClient) {

		Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
		if (CollectionUtils.isEmpty(parameters) || !authorizationCodeGrant(parameters)) {
			return false;
		}

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				(String) parameters.get(OAuth2ParameterNames.CODE),
				AUTHORIZATION_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throwInvalidClient();
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationRequest.class.getName());

		String codeChallenge = (String) authorizationRequest.getAdditionalParameters()
				.get(PkceParameterNames.CODE_CHALLENGE);
		if (!StringUtils.hasText(codeChallenge) &&
				registeredClient.getClientSettings().requireProofKey()) {
			throwInvalidClient();
		}

		String codeChallengeMethod = (String) authorizationRequest.getAdditionalParameters()
				.get(PkceParameterNames.CODE_CHALLENGE_METHOD);
		String codeVerifier = (String) parameters.get(PkceParameterNames.CODE_VERIFIER);
		if (!codeVerifierValid(codeVerifier, codeChallenge, codeChallengeMethod)) {
			throwInvalidClient();
		}

		return true;
	}

	private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
		return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
				parameters.get(OAuth2ParameterNames.GRANT_TYPE)) &&
				parameters.get(OAuth2ParameterNames.CODE) != null;
	}

	private static boolean codeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
		if (!StringUtils.hasText(codeVerifier)) {
			return false;
		} else if (!StringUtils.hasText(codeChallengeMethod) || PkceCodeChallengeMethod2.PLAIN.getValue().equals(codeChallengeMethod)) {
			return  codeVerifier.equals(codeChallenge);
		} else if (PkceCodeChallengeMethod2.S256.getValue().equals(codeChallengeMethod)) {
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
				String encodedVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
				return encodedVerifier.equals(codeChallenge);
			} catch (NoSuchAlgorithmException ex) {
				// It is unlikely that SHA-256 is not available on the server. If it is not available,
				// there will likely be bigger issues as well. We default to SERVER_ERROR.
			}
		}
		throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
	}

	private static void throwInvalidClient() {
		throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
	}
}
