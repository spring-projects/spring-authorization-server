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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.UUID;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect Dynamic Client Registration 1.0.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @since 0.1.1
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">3. Client Registration Endpoint</a>
 */
public class OidcClientRegistrationAuthenticationProvider implements AuthenticationProvider {
	private static final StringKeyGenerator CLIENT_ID_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 32);
	private static final StringKeyGenerator CLIENT_SECRET_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 48);
	private static final String DEFAULT_AUTHORIZED_SCOPE = "client.create";
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication =
				(OidcClientRegistrationAuthenticationToken) authentication;

		// Validate the "initial" access token
		AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication = null;
		if (AbstractOAuth2TokenAuthenticationToken.class.isAssignableFrom(clientRegistrationAuthentication.getPrincipal().getClass())) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken<?>) clientRegistrationAuthentication.getPrincipal();
		}
		if (accessTokenAuthentication == null || !accessTokenAuthentication.isAuthenticated()) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		}

		String accessTokenValue = accessTokenAuthentication.getToken().getTokenValue();

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				accessTokenValue, OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		}

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		if (!authorizedAccessToken.isActive()) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		}

		if (!isAuthorized(authorizedAccessToken)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE));
		}

		RegisteredClient registeredClient = create(clientRegistrationAuthentication.getClientRegistration());
		this.registeredClientRepository.save(registeredClient);

		// Invalidate the "initial" access token as it can only be used once
		authorization = OidcAuthenticationProviderUtils.invalidate(authorization, authorizedAccessToken.getToken());
		if (authorization.getRefreshToken() != null) {
			authorization = OidcAuthenticationProviderUtils.invalidate(authorization, authorization.getRefreshToken().getToken());
		}
		this.authorizationService.save(authorization);

		return new OidcClientRegistrationAuthenticationToken(
				accessTokenAuthentication, convert(registeredClient));
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	@SuppressWarnings("unchecked")
	private static boolean isAuthorized(OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken) {
		Object scope = authorizedAccessToken.getClaims().get(OAuth2ParameterNames.SCOPE);
		return scope != null && ((Collection<String>) scope).contains(DEFAULT_AUTHORIZED_SCOPE);
	}

	private static RegisteredClient create(OidcClientRegistration clientRegistration) {
		// @formatter:off
		RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(CLIENT_ID_GENERATOR.generateKey())
				.clientIdIssuedAt(Instant.now())
				.clientSecret(CLIENT_SECRET_GENERATOR.generateKey())
				.clientName(clientRegistration.getClientName());

		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		} else {
			builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		}

		// TODO Validate redirect_uris and throw OAuth2ErrorCodes2.INVALID_REDIRECT_URI on error
		builder.redirectUris(redirectUris ->
				redirectUris.addAll(clientRegistration.getRedirectUris()));

		if (!CollectionUtils.isEmpty(clientRegistration.getGrantTypes())) {
			builder.authorizationGrantTypes(authorizationGrantTypes ->
					clientRegistration.getGrantTypes().forEach(grantType ->
							authorizationGrantTypes.add(new AuthorizationGrantType(grantType))));
		} else {
			builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		}
		if (CollectionUtils.isEmpty(clientRegistration.getResponseTypes()) ||
				clientRegistration.getResponseTypes().contains(OAuth2AuthorizationResponseType.CODE.getValue())) {
			builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		}

		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			builder.scopes(scopes ->
					scopes.addAll(clientRegistration.getScopes()));
		}

		builder
				.clientSettings(clientSettings ->
						clientSettings
								.requireProofKey(true)
								.requireUserConsent(true))
				.tokenSettings(tokenSettings ->
						tokenSettings
								.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256));

		return builder.build();
		// @formatter:on
	}

	private static OidcClientRegistration convert(RegisteredClient registeredClient) {
		// @formatter:off
		OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
				.clientId(registeredClient.getClientId())
				.clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
				.clientSecret(registeredClient.getClientSecret())
				.clientName(registeredClient.getClientName());

		builder.redirectUris(redirectUris ->
				redirectUris.addAll(registeredClient.getRedirectUris()));

		builder.grantTypes(grantTypes ->
				registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
						grantTypes.add(authorizationGrantType.getValue())));

		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			builder.responseType(OAuth2AuthorizationResponseType.CODE.getValue());
		}

		if (!CollectionUtils.isEmpty(registeredClient.getScopes())) {
			builder.scopes(scopes ->
					scopes.addAll(registeredClient.getScopes()));
		}

		builder
				.tokenEndpointAuthenticationMethod(registeredClient.getClientAuthenticationMethods().iterator().next().getValue())
				.idTokenSignedResponseAlgorithm(registeredClient.getTokenSettings().idTokenSignatureAlgorithm().getName());

		return builder.build();
		// @formatter:on
	}

}
