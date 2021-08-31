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

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect Dynamic Client Registration 1.0 and
 * OpenID Connect Client Configuration 1.0.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @since 0.1.1
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">3. Client Registration Endpoint</a>
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientConfigurationEndpoint">4. Client Configuration Endpoint</a>
 */
public final class OidcClientRegistrationAuthenticationProvider implements AuthenticationProvider {
	private static final StringKeyGenerator CLIENT_ID_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 32);
	private static final StringKeyGenerator CLIENT_SECRET_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 48);
	private static final String DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE = "client.create";
	private static final String DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE = "client.read";
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
	private ProviderSettings providerSettings;

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
	}

	@Autowired(required = false)
	protected void setProviderSettings(ProviderSettings providerSettings) {
		this.providerSettings = providerSettings;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication =
				(OidcClientRegistrationAuthenticationToken) authentication;

		// Validate the "initial" and the registration access token
		AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication = null;
		if (AbstractOAuth2TokenAuthenticationToken.class.isAssignableFrom(clientRegistrationAuthentication.getPrincipal().getClass())) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken<?>) clientRegistrationAuthentication.getPrincipal();
		}
		if (accessTokenAuthentication == null || !accessTokenAuthentication.isAuthenticated()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		String accessTokenValue = accessTokenAuthentication.getToken().getTokenValue();

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				accessTokenValue, OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		if (!authorizedAccessToken.isActive()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		if (clientRegistrationAuthentication.getClientRegistration() != null) {

			return registerClient(clientRegistrationAuthentication, authorization);
		}

		if (isNotAuthorized(authorizedAccessToken, DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		}

		RegisteredClient registeredClient = this.registeredClientRepository
				.findByClientId(clientRegistrationAuthentication.getClientId());

		if (registeredClient == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}
		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		String registrationClientUri = registrationClientUri(getIssuer(), this.providerSettings.getOidcClientRegistrationEndpoint(), registeredClient.getClientId());
		return new OidcClientRegistrationAuthenticationToken(accessTokenAuthentication,
				convert(registeredClient, registrationClientUri, null));

	}

	private OidcClientRegistrationAuthenticationToken registerClient(OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication,
			OAuth2Authorization authorization) {

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		if (isNotAuthorized(authorizedAccessToken, DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		}

		if (!isValidRedirectUris(clientRegistrationAuthentication.getClientRegistration().getRedirectUris())) {
			// TODO Add OAuth2ErrorCodes.INVALID_REDIRECT_URI
			throw new OAuth2AuthenticationException("invalid_redirect_uri");
		}

		RegisteredClient registeredClient = create(clientRegistrationAuthentication.getClientRegistration());
		this.registeredClientRepository.save(registeredClient);

		// Invalidate the "initial" access token as it can only be used once
		authorization = OidcAuthenticationProviderUtils.invalidate(authorization, authorizedAccessToken.getToken());
		if (authorization.getRefreshToken() != null) {
			authorization = OidcAuthenticationProviderUtils.invalidate(authorization, authorization.getRefreshToken().getToken());
		}
		this.authorizationService.save(authorization);
		String registrationClientUri = registrationClientUri(getIssuer(), this.providerSettings.getOidcClientRegistrationEndpoint(), registeredClient.getClientId());
		String registrationAccessToken = registerAccessToken(registeredClient)
				.getAccessToken().getToken().getTokenValue();

		return new OidcClientRegistrationAuthenticationToken((AbstractOAuth2TokenAuthenticationToken<?>) clientRegistrationAuthentication.getPrincipal(),
				convert(registeredClient, registrationClientUri, registrationAccessToken));
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private String getIssuer() {
		return this.providerSettings != null ? this.providerSettings.getIssuer() : null;
	}

	private OAuth2Authorization registerAccessToken(RegisteredClient registeredClient) {

		String issuer = getIssuer();
		Set<String> authorizedScopes = new HashSet<>();
		authorizedScopes.add(DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE);
		JoseHeader headers = JwtUtils.headers().build();
		JwtClaimsSet claims = JwtUtils.accessTokenClaims(
				registeredClient, issuer, registeredClient.getClientId(), authorizedScopes).build();

		Jwt registrationAccessToken = this.jwtEncoder.encode(headers, claims);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				registrationAccessToken.getTokenValue(), registrationAccessToken.getIssuedAt(),
				registrationAccessToken.getExpiresAt(), authorizedScopes);

		// @formatter:off
		OAuth2Authorization accessTokenAuthorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.token(accessToken,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, registrationAccessToken.getClaims()))
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
				.build();
		// @formatter:on

		this.authorizationService.save(accessTokenAuthorization);
		return accessTokenAuthorization;
	}

	@SuppressWarnings("unchecked")
	private static boolean isNotAuthorized(OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken, String requiredScope) {
		Object scope = authorizedAccessToken.getClaims().get(OAuth2ParameterNames.SCOPE);
		return scope == null || !((Collection<String>) scope).contains(requiredScope);
	}

	private static boolean isValidRedirectUris(List<String> redirectUris) {
		if (CollectionUtils.isEmpty(redirectUris)) {
			return true;
		}

		for (String redirectUri : redirectUris) {
			try {
				URI validRedirectUri = new URI(redirectUri);
				if (validRedirectUri.getFragment() != null) {
					return false;
				}
			} catch (URISyntaxException ex) {
				return false;
			}
		}

		return true;
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
				.clientSettings(ClientSettings.builder()
						.requireProofKey(true)
						.requireAuthorizationConsent(true)
						.build())
				.tokenSettings(TokenSettings.builder()
						.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
						.build());

		return builder.build();
		// @formatter:on
	}


	private static String registrationClientUri(String issuer, String oidcClientRegistrationEndpoint, String clientId){
		return UriComponentsBuilder.fromUriString(issuer)
				.path(oidcClientRegistrationEndpoint)
				.queryParam(OAuth2ParameterNames.CLIENT_ID, clientId).toUriString();
	}

	private static OidcClientRegistration convert(RegisteredClient registeredClient, String registrationClientUri,
			@Nullable String registrationAccessToken) {
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
				.idTokenSignedResponseAlgorithm(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName())
				.registrationClientUri(registrationClientUri);
		if (StringUtils.hasText(registrationAccessToken)) {
			builder.registrationAccessToken(registrationAccessToken);
		}
		return builder.build();
		// @formatter:on
	}

}
