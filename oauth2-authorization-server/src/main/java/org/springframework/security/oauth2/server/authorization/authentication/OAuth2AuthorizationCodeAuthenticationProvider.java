/*
 * Copyright 2020 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationAttributeNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenMetadata;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Set;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2AuthorizationCodeAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
				(OAuth2AuthorizationCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(authorizationCodeAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				authorizationCodeAuthentication.getCode(), TokenType.AUTHORIZATION_CODE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}
		OAuth2AuthorizationCode authorizationCode = authorization.getTokens().getToken(OAuth2AuthorizationCode.class);
		OAuth2TokenMetadata authorizationCodeMetadata = authorization.getTokens().getTokenMetadata(authorizationCode);

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST);

		if (!registeredClient.getClientId().equals(authorizationRequest.getClientId())) {
			if (!authorizationCodeMetadata.isInvalidated()) {
				// Invalidate the authorization code given that a different client is attempting to use it
				authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode);
				this.authorizationService.save(authorization);
			}
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		if (StringUtils.hasText(authorizationRequest.getRedirectUri()) &&
				!authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		if (authorizationCodeMetadata.isInvalidated()) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}

		Set<String> authorizedScopes = authorization.getAttribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES);
		Jwt jwt = OAuth2TokenIssuerUtil
			.issueJwtAccessToken(this.jwtEncoder, authorization.getPrincipalName(), registeredClient.getClientId(), authorizedScopes, registeredClient.getTokenSettings().accessTokenTimeToLive());
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), authorizedScopes);

		OAuth2Tokens.Builder tokensBuilder = OAuth2Tokens.from(authorization.getTokens())
				.accessToken(accessToken);

		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			refreshToken = OAuth2TokenIssuerUtil.issueRefreshToken(registeredClient.getTokenSettings().refreshTokenTimeToLive());
			tokensBuilder.refreshToken(refreshToken);
		}

		OAuth2Tokens tokens = tokensBuilder.build();
		authorization = OAuth2Authorization.from(authorization)
				.tokens(tokens)
				.attribute(OAuth2AuthorizationAttributeNames.ACCESS_TOKEN_ATTRIBUTES, jwt)
				.build();

		// Invalidate the authorization code as it can only be used once
		authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, authorizationCode);

		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
