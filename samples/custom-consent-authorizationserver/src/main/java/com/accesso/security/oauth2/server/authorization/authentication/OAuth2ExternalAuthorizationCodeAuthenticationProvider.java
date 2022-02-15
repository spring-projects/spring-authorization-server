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
package com.accesso.security.oauth2.server.authorization.authentication;

import com.accesso.security.oauth2.server.authorization.config.ClientExternalAuthenticationConfig;
import com.accesso.security.oauth2.server.authorization.config.ClientExternalAuthenticationConfig.ClientExternalAuthConfig;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.JwtUtils;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AnonymousUserGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see OAuth2TokenCustomizer
 * @see JwtEncodingContext
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public final class OAuth2ExternalAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
			new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE =
			new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
	private static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private final Map<String, ClientExternalAuthenticationConfig.ClientExternalAuthConfig> clientConfig;
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
	private final ScopeMapper scopeMapper = new ScopeMapper();
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};
	private Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2ExternalAuthorizationCodeAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			ClientExternalAuthenticationConfig clientConfig, JwtEncoder jwtEncoder) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.clientConfig = clientConfig.getConfig();
		this.jwtEncoder = jwtEncoder;
	}

	/**
	 * Sets the {@link OAuth2TokenCustomizer} that customizes the
	 * {@link JwtEncodingContext.Builder#headers(Consumer) headers} and/or
	 * {@link JwtEncodingContext.Builder#claims(Consumer) claims} for the generated {@link Jwt}.
	 *
	 * @param jwtCustomizer the {@link OAuth2TokenCustomizer} that customizes the headers and/or claims for the generated {@code Jwt}
	 */
	public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	/**
	 * Sets the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}.
	 *
	 * @param refreshTokenGenerator the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}
	 */
	public void setRefreshTokenGenerator(Supplier<String> refreshTokenGenerator) {
		Assert.notNull(refreshTokenGenerator, "refreshTokenGenerator cannot be null");
		this.refreshTokenGenerator = refreshTokenGenerator;
	}

	@Deprecated
	protected void setProviderSettings(ProviderSettings providerSettings) {
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
				(OAuth2AuthorizationCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(authorizationCodeAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		// The authorization_code was externally generated, so the way that we validate it here
		// is by interacting with the upstream auth service to get the access_token.  If that succeeds,
		// then we can wrap it and return it in a token of our own making.
		String clientId = registeredClient.getClientId();
		ClientExternalAuthConfig clientExternalConfig = clientConfig.get(clientId);
		if (clientExternalConfig == null) {
			// Let the other Authentication Providers handle this case.
			return null;
		}

		// Create the ClientRegistration to use as an OAuth2 client with th external server's token endpoint.
		ClientRegistration clientRegistration = externalClientRegistration(authorizationCodeAuthentication,
				registeredClient, clientExternalConfig);
		// Attempt to reconstruct/infer the prior authorization code exchange - the Spring OAuth2 client libs
		// use this to compose the token request and ensure consistency with the original authorization code request
		OAuth2AuthorizationExchange imaginedAuthorizationExchange = this.createExchange(authorizationCodeAuthentication,
				registeredClient, clientExternalConfig);

		// All the token endpoint of the external service.
		OAuth2AuthorizationCodeGrantRequest request = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				imaginedAuthorizationExchange);
		DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
		OAuth2AccessTokenResponse response = client.getTokenResponse(request);
		OAuth2AccessToken extAccessToken = response.getAccessToken();
		OAuth2RefreshToken extRefreshToken = response.getRefreshToken();

		// Federated Identity always requires OIDC (scope includes openid) to be in the requests and
		// supported by the upstream service.  It is the only way we can know who logged in and create the
		// associated account in TE2.
		if (! response.getAdditionalParameters().containsKey(OidcParameterNames.ID_TOKEN)) {
			throw new OAuth2AuthenticationException("Use of Federate identity requires an upstream server that supports OIDC (id_token)");
		}
		OidcIdToken idtoken = decodeIdToken(clientExternalConfig,
				(String)response.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN));
		OidcUserInfo userInfo = new OidcUserInfo(idtoken.getClaims());

		// This code copies from OidcUserService - showing how an OidcUser is constructed...
		// We establish the granted authorities for this user.
		Set<GrantedAuthority> authorities = new LinkedHashSet<>();
		authorities.add(new OidcUserAuthority(idtoken, userInfo));
		OAuth2AccessToken token = extAccessToken;
		for (String authority : token.getScopes()) {
			authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
		}
		OidcUser oidcUser = new DefaultOidcUser(authorities, idtoken, userInfo);
		// This seemed like the right thing to use to express the Principal.
		OAuth2AuthenticationToken principal = new OAuth2AuthenticationToken(oidcUser, authorities, registeredClient.getId()) ;

		// We construct an Authorization object on par with what would have been
		// in the database if we had issued the authentication code.
		OAuth2Authorization authorization = OAuth2Authorization
				.withRegisteredClient(registeredClient)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(Principal.class.getName(), principal)
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, extAccessToken.getScopes())
				.principalName(bestPrinciple(idtoken))
				.build();

		// ===============================
		// From here on it's the same code as in the OAuth2AuthorizationCodeAuthenticationProvider
		// based on a constructed OAuth2Authorization object.  This should probably be moved into a common function
		// All code that has been changed is prefixed with "//#".
		// ===============================

		String issuer = ProviderContextHolder.getProviderContext().getIssuer();
		Set<String> authorizedScopes = authorization.getAttribute(
				OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);

		JoseHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, authorization.getPrincipalName(),
				authorizedScopes);

		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorization(authorization)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationCodeAuthentication)
				.build();
		// @formatter:on

		this.jwtCustomizer.customize(context);

		JoseHeader headers = context.getHeaders().build();
		JwtClaimsSet claims = context.getClaims().build();
		Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
				jwtAccessToken.getExpiresAt(), authorizedScopes);

		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
				// Do not issue refresh token to public client
				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
			refreshToken = generateRefreshToken(registeredClient.getTokenSettings().getRefreshTokenTimeToLive());
		}

		Jwt jwtIdToken = null;

		// The scopes requested originally are not in the authorizationCodeAuthentication obj, they are in the
		// response from the token request however.
		//# if (authorizationRequest.getScopes().contains(OidcScopes.OPENID)) {
		if (response.getAdditionalParameters().containsKey(OidcParameterNames.ID_TOKEN)) {
			//# String nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);
			String nonce = idtoken.getNonce();

			headersBuilder = JwtUtils.headers();
			claimsBuilder = JwtUtils.idTokenClaims(
					registeredClient, issuer, authorization.getPrincipalName(), nonce);

			// @formatter:off
			context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
					.registeredClient(registeredClient)
					.principal(authorization.getAttribute(Principal.class.getName()))
					.authorization(authorization)
					.authorizedScopes(authorizedScopes)
					.tokenType(ID_TOKEN_TOKEN_TYPE)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.authorizationGrant(authorizationCodeAuthentication)
					.build();
			// @formatter:on

			this.jwtCustomizer.customize(context);

			headers = context.getHeaders().build();
			claims = context.getClaims().build();
			jwtIdToken = this.jwtEncoder.encode(headers, claims);
		}

		OidcIdToken idToken;
		if (jwtIdToken != null) {
			idToken = new OidcIdToken(jwtIdToken.getTokenValue(), jwtIdToken.getIssuedAt(),
					jwtIdToken.getExpiresAt(), jwtIdToken.getClaims());
		} else {
			idToken = null;
		}

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.
				from(authorization)
				.token(accessToken,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims())
				);
		if (refreshToken != null) {
			authorizationBuilder.refreshToken(refreshToken);
		}
		if (idToken != null) {
			authorizationBuilder
					.token(idToken,
							(metadata) ->
									metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		}
		authorization = authorizationBuilder.build();
		// @formatter:on

		// Don't need this here:
		//# Invalidate the authorization code as it can only be used once
		//# authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode.getToken());

		this.authorizationService.save(authorization);

		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (idToken != null) {
			additionalParameters = new HashMap<>();
			additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
		}

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
	}

	private class OrganizationSubClaimAdapter implements
			Converter<Map<String, Object>, Map<String, Object>> {

		private final MappedJwtClaimSetConverter delegate =
				MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

		public Map<String, Object> convert(Map<String, Object> claims) {
			Map<String, Object> convertedClaims = this.delegate.convert(claims);
			String organization = convertedClaims.get("organization") != null ?
					(String) convertedClaims.get("organization") : "unknown";

			convertedClaims.put("organization", organization.toUpperCase());

			return convertedClaims;
		}
	}

	private OidcIdToken decodeIdToken(ClientExternalAuthConfig clientExternalAuthConfig, String idtoken) {
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(
				clientExternalAuthConfig.getJwkUri()).build();

		jwtDecoder.setClaimSetConverter(new OrganizationSubClaimAdapter());
		Jwt jwt = jwtDecoder.decode(idtoken);
		return OidcIdToken.withTokenValue(idtoken)
				.claims(map -> map.putAll(jwt.getClaims()))
				.build();
	}

	/**
	 * Creates a ClientRegistration representing the client that called our server with the externally issued
	 * autorization code.  We based this on the actual RegisteredClient along with the additional details for how
	 * the interaction should be conducted with the external client, per ClientExternalAuthConfig
	 * @param token
	 * @param registeredClient
	 * @param clientExternalConfig
	 * @return
	 */
	private ClientRegistration externalClientRegistration(OAuth2AuthorizationCodeAuthenticationToken token,
			RegisteredClient registeredClient, ClientExternalAuthConfig clientExternalConfig) {
		return ClientRegistration
				.withRegistrationId(registeredClient.getClientId())
				.clientId(clientExternalConfig.getExtClientId())
				.clientSecret(clientExternalConfig.getExtClientSecret())
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.tokenUri(clientExternalConfig.getTokenUri())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri(token.getRedirectUri())  // actual redirect_uri used in call to us.
				.scope(scopeMapper.mapScopes(clientExternalConfig, registeredClient.getScopes()))
				.build();
	}

	/**
	 * Creates an OAuth2AuthorizationExchange representing our original redirect of the client to the
	 * external authorization URL, and it's (likely) response back to the client.  We don't know exactly what
	 * response was sent to the client, because we didn't send it.  The only reason we construct this object is
	 * to reuse the OAuth2AuthorizationCodeGrantRequest.getTokenResponse() as a way to reuse oauth-client lib
	 * and thus is for convenience.
	 * @param authentication
	 * @return
	 */
	private OAuth2AuthorizationExchange createExchange(OAuth2AuthorizationCodeAuthenticationToken token,
			RegisteredClient registeredClient, ClientExternalAuthConfig clientExternalConfig) {

		Object state = token.getAdditionalParameters().get(OAuth2ParameterNames.STATE);
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest
				.authorizationCode()
				.authorizationRequestUri(clientExternalConfig.getIssuerUri())
				.authorizationUri(clientExternalConfig.getIssuerUri())
				.clientId(clientExternalConfig.getExtClientId())
				.scopes(scopeMapper.mapScopes(clientExternalConfig, registeredClient.getScopes()))
				.redirectUri(token.getRedirectUri())
				.state(state != null ? state.toString(): null)
				.build();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse
				.success(token.getCode())
				.redirectUri(token.getRedirectUri())
				.state(state != null ? state.toString(): null)
				.build();
		OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
		return authorizationExchange;
	}

	private String bestPrinciple(OidcIdToken token) {
		return (! ObjectUtils.isEmpty(token.getEmail())) ? token.getEmail() :
				(! ObjectUtils.isEmpty(token.getSubject())) ? token.getSubject() :
						null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(tokenTimeToLive);
		return new OAuth2RefreshToken(this.refreshTokenGenerator.get(), issuedAt, expiresAt);
	}

}
