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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} implementation for OpenID Connect 1.0 Dynamic Client Registration (and Configuration) Endpoint.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @author Rafal Lewczuk
 * @since 0.1.1
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">3. Client Registration Endpoint</a>
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientConfigurationEndpoint">4. Client Configuration Endpoint</a>
 */
public final class OidcClientRegistrationAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError";
	private static final StringKeyGenerator CLIENT_ID_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 32);
	private static final StringKeyGenerator CLIENT_SECRET_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 48);
	private static final String DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE = "client.create";
	private static final String DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE = "client.read";
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @deprecated Use {@link #OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository, OAuth2AuthorizationService, JwtEncoder)} instead
	 */
	@Deprecated
	public OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 * @deprecated Use {@link #OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository, OAuth2AuthorizationService, OAuth2TokenGenerator)} instead
	 */
	@Deprecated
	public OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.tokenGenerator = new JwtGenerator(jwtEncoder);
	}

	/**
	 * Constructs an {@code OidcClientRegistrationAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param tokenGenerator the token generator
	 * @since 0.2.3
	 */
	public OidcClientRegistrationAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	@Deprecated
	@Autowired(required = false)
	protected void setJwtEncoder(JwtEncoder jwtEncoder) {
		this.tokenGenerator = new JwtGenerator(jwtEncoder);
	}

	@Deprecated
	protected void setProviderSettings(ProviderSettings providerSettings) {
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication =
				(OidcClientRegistrationAuthenticationToken) authentication;

		// Validate the "initial" or "registration" access token
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

		return clientRegistrationAuthentication.getClientRegistration() != null ?
				registerClient(clientRegistrationAuthentication, authorization) :
				findRegistration(clientRegistrationAuthentication, authorization);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private OidcClientRegistrationAuthenticationToken findRegistration(OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication,
			OAuth2Authorization authorization) {

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		checkScopeForConfiguration(authorizedAccessToken);

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				clientRegistrationAuthentication.getClientId());
		if (registeredClient == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
		}

		OidcClientRegistration clientRegistration = buildRegistration(registeredClient).build();

		return new OidcClientRegistrationAuthenticationToken(
				(Authentication) clientRegistrationAuthentication.getPrincipal(), clientRegistration);
	}

	private OidcClientRegistrationAuthenticationToken registerClient(OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication,
			OAuth2Authorization authorization) {

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		checkScopeForRegistration(authorizedAccessToken);

		if (!isValidRedirectUris(clientRegistrationAuthentication.getClientRegistration().getRedirectUris())) {
			// TODO Add OAuth2ErrorCodes.INVALID_REDIRECT_URI
			throwInvalidClientRegistration("invalid_redirect_uri", OidcClientMetadataClaimNames.REDIRECT_URIS);
		}

		if (!isValidTokenEndpointAuthenticationMethod(clientRegistrationAuthentication.getClientRegistration())) {
			// TODO Add OAuth2ErrorCodes.INVALID_CLIENT_METADATA
			throwInvalidClientRegistration("invalid_client_metadata", OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
		}

		RegisteredClient registeredClient = createClient(clientRegistrationAuthentication.getClientRegistration());
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization registeredClientAuthorization = registerAccessToken(registeredClient);

		// Invalidate the "initial" access token as it can only be used once
		authorization = OidcAuthenticationProviderUtils.invalidate(authorization, authorizedAccessToken.getToken());
		if (authorization.getRefreshToken() != null) {
			authorization = OidcAuthenticationProviderUtils.invalidate(authorization, authorization.getRefreshToken().getToken());
		}
		this.authorizationService.save(authorization);

		OidcClientRegistration clientRegistration = buildRegistration(registeredClient)
				.registrationAccessToken(registeredClientAuthorization.getAccessToken().getToken().getTokenValue())
				.build();

		return new OidcClientRegistrationAuthenticationToken(
				(Authentication) clientRegistrationAuthentication.getPrincipal(), clientRegistration);
	}

	private OAuth2Authorization registerAccessToken(RegisteredClient registeredClient) {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				registeredClient.getClientAuthenticationMethods().iterator().next(), registeredClient.getClientSecret());

		Set<String> authorizedScopes = new HashSet<>();
		authorizedScopes.add(DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE);
		authorizedScopes = Collections.unmodifiableSet(authorizedScopes);

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.providerContext(ProviderContextHolder.getProviderContext())
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
		// @formatter:on

		OAuth2Token registrationAccessToken = this.tokenGenerator.generate(tokenContext);
		if (registrationAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the registration access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				registrationAccessToken.getTokenValue(), registrationAccessToken.getIssuedAt(),
				registrationAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes);
		// @formatter:on
		if (registrationAccessToken instanceof Jwt) {
			authorizationBuilder.token(accessToken, (metadata) ->
					metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((Jwt) registrationAccessToken).getClaims()));
		} else {
			authorizationBuilder.accessToken(accessToken);
		}

		OAuth2Authorization authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		return authorization;
	}

	private OidcClientRegistration.Builder buildRegistration(RegisteredClient registeredClient) {
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

		ProviderContext providerContext = ProviderContextHolder.getProviderContext();
		String registrationClientUri = UriComponentsBuilder.fromUriString(providerContext.getIssuer())
				.path(providerContext.getProviderSettings().getOidcClientRegistrationEndpoint())
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.toUriString();

		builder
				.tokenEndpointAuthenticationMethod(registeredClient.getClientAuthenticationMethods().iterator().next().getValue())
				.idTokenSignedResponseAlgorithm(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName())
				.registrationClientUrl(registrationClientUri);

		ClientSettings clientSettings = registeredClient.getClientSettings();

		if (clientSettings.getJwkSetUrl() != null) {
			builder.jwkSetUrl(clientSettings.getJwkSetUrl());
		}

		if (clientSettings.getTokenEndpointAuthenticationSigningAlgorithm() != null) {
			builder.tokenEndpointAuthenticationSigningAlgorithm(clientSettings.getTokenEndpointAuthenticationSigningAlgorithm().getName());
		}

		return builder;
		// @formatter:on
	}

	private static void checkScopeForRegistration(OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken) {
		checkScope(authorizedAccessToken, Collections.singleton(DEFAULT_CLIENT_REGISTRATION_AUTHORIZED_SCOPE));
	}

	private static void checkScopeForConfiguration(OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken) {
		checkScope(authorizedAccessToken, Collections.singleton(DEFAULT_CLIENT_CONFIGURATION_AUTHORIZED_SCOPE));
	}

	@SuppressWarnings("unchecked")
	private static void checkScope(OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken, Set<String> requiredScope) {
		Collection<String> authorizedScope = Collections.emptySet();
		if (authorizedAccessToken.getClaims().containsKey(OAuth2ParameterNames.SCOPE)) {
			authorizedScope = (Collection<String>) authorizedAccessToken.getClaims().get(OAuth2ParameterNames.SCOPE);
		}
		if (!authorizedScope.containsAll(requiredScope)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		} else if (authorizedScope.size() != requiredScope.size()) {
			// Restrict the access token to only contain the required scope
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}
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

	private static boolean isValidTokenEndpointAuthenticationMethod(OidcClientRegistration clientRegistration) {
		String authenticationMethod = clientRegistration.getTokenEndpointAuthenticationMethod();
		String authenticationSigningAlgorithm = clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm();

		if (!ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(authenticationMethod) &&
				!ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(authenticationMethod)) {
			return !StringUtils.hasText(authenticationSigningAlgorithm);
		}

		if ("none".equals(authenticationSigningAlgorithm)) {
			return false;
		}

		if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(authenticationMethod)) {
			return clientRegistration.getJwkSetUrl() != null &&
					(!StringUtils.hasText(authenticationSigningAlgorithm) ||
							SignatureAlgorithm.from(authenticationSigningAlgorithm) != null);
		} else {
			// client_secret_jwt
			return !StringUtils.hasText(authenticationSigningAlgorithm) ||
					MacAlgorithm.from(authenticationSigningAlgorithm) != null;
		}
	}

	private static RegisteredClient createClient(OidcClientRegistration clientRegistration) {
		// @formatter:off
		RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(CLIENT_ID_GENERATOR.generateKey())
				.clientIdIssuedAt(Instant.now())
				.clientSecret(CLIENT_SECRET_GENERATOR.generateKey())
				.clientName(clientRegistration.getClientName());

		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
		} else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
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

		ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
				.requireProofKey(true)
				.requireAuthorizationConsent(true);

		if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			MacAlgorithm macAlgorithm = MacAlgorithm.from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
			if (macAlgorithm == null) {
				macAlgorithm = MacAlgorithm.HS256;
			}
			clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(macAlgorithm);
		} else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
			if (signatureAlgorithm == null) {
				signatureAlgorithm = SignatureAlgorithm.RS256;
			}
			clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(signatureAlgorithm);
			clientSettingsBuilder.jwkSetUrl(clientRegistration.getJwkSetUrl().toString());
		}

		builder
				.clientSettings(clientSettingsBuilder.build())
				.tokenSettings(TokenSettings.builder()
						.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
						.build());

		return builder.build();
		// @formatter:on
	}

	private static void throwInvalidClientRegistration(String errorCode, String fieldName) {
		OAuth2Error error = new OAuth2Error(
				errorCode,
				"Invalid Client Registration: " + fieldName,
				ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
