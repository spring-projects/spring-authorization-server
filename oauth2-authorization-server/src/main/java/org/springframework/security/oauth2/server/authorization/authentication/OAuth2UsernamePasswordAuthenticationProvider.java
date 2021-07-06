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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Password Grant.
 *
 * @author leegecho
 * @see OAuth2UsernamePasswordAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see OAuth2TokenCustomizer
 * @see JwtEncodingContext
 * @since 0.1.2
 */
public class OAuth2UsernamePasswordAuthenticationProvider extends DaoAuthenticationProvider {

	protected final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};
	private ProviderSettings providerSettings;

	public OAuth2UsernamePasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService, UserDetailsService userDetailsService, JwtEncoder jwtEncoder) {
		this.authorizationService = authorizationService;
		setUserDetailsService(userDetailsService);
		this.jwtEncoder = jwtEncoder;
	}

	public final void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	@Autowired(required = false)
	protected void setProviderSettings(ProviderSettings providerSettings) {
		this.providerSettings = providerSettings;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2UsernamePasswordAuthenticationToken passwordAuthentication = (OAuth2UsernamePasswordAuthenticationToken) authentication;
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(passwordAuthentication.getUsername(), passwordAuthentication.getPassword());
		token = (UsernamePasswordAuthenticationToken) super.authenticate(token);

		return createSuccessAuthentication(passwordAuthentication, token);
	}

	protected Authentication createSuccessAuthentication(OAuth2UsernamePasswordAuthenticationToken authentication,
			UsernamePasswordAuthenticationToken token) {

		String username = ((User) token.getPrincipal()).getUsername();
		OAuth2UsernamePasswordAuthenticationToken result = new OAuth2UsernamePasswordAuthenticationToken(
				authentication.getClientPrincipal(), username, authentication.getPassword(),
				authentication.getAdditionalParameters(), token.getAuthorities());
		result.setDetails(authentication.getDetails());
		this.logger.debug("Authenticated user");

		OAuth2ClientAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(authentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		Assert.notNull(registeredClient, "registeredClient cannot be null");

		Object scopeObject = authentication.getAdditionalParameters().get(OAuth2ParameterNames.SCOPE);
		String[] scopes = scopeObject != null ? scopeObject.toString().split("[, ;]]") : new String[0];
		Set<String> authorizedScopes = new HashSet<>();
		Collections.addAll(authorizedScopes, scopes);

		String issuer = this.providerSettings != null ? this.providerSettings.issuer() : null;

		JoseHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, username,
				authorizedScopes);

		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(result)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.authorizationGrant(authentication)
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
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			refreshToken = OAuth2RefreshTokenAuthenticationProvider.generateRefreshToken(
					registeredClient.getTokenSettings().refreshTokenTimeToLive());
		}

		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(username)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.token(accessToken,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims()))
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
				.build();
		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
