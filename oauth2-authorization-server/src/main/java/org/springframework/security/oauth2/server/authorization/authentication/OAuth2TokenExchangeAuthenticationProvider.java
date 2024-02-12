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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Token Exchange Grant.
 *
 * @author Steve Riesenberg
 * @since 1.3
 * @see OAuth2TokenExchangeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8693#section-1">Section 1 Introduction</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8693#section-2.1">Section 2.1 Request</a>
 */
public final class OAuth2TokenExchangeAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final AuthorizationGrantType TOKEN_EXCHANGE = new AuthorizationGrantType(
			"urn:ietf:params:oauth:grant-type:token-exchange");

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private static final String MAY_ACT = "may_act";

	private static final String ISSUED_TOKEN_TYPE = "issued_token_type";

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	/**
	 * Constructs an {@code OAuth2TokenExchangeAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param tokenGenerator the token generator
	 */
	public OAuth2TokenExchangeAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication =
			(OAuth2TokenExchangeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
			getAuthenticatedClientElseThrowInvalidClient(tokenExchangeAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(TOKEN_EXCHANGE)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		if (JWT_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getRequestedTokenType()) &&
				!OAuth2TokenFormat.SELF_CONTAINED.equals(registeredClient.getTokenSettings().getAccessTokenFormat())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		OAuth2Authorization subjectAuthorization = this.authorizationService.findByToken(
			tokenExchangeAuthentication.getSubjectToken(), OAuth2TokenType.ACCESS_TOKEN);
		if (subjectAuthorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with subject token");
		}

		OAuth2Authorization.Token<OAuth2Token> subjectToken = subjectAuthorization.getToken(
				tokenExchangeAuthentication.getSubjectToken());
		if (!subjectToken.isActive()) {
			// As per https://tools.ietf.org/html/rfc6749#section-5.2
			// invalid_grant: The provided authorization grant (e.g., authorization code,
			// resource owner credentials) or refresh token is invalid, expired, revoked [...].
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (JWT_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getSubjectTokenType()) &&
				!Jwt.class.isAssignableFrom(subjectToken.getToken().getClass())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		if (subjectAuthorization.getAttribute(Principal.class.getName()) == null) {
			// As per https://datatracker.ietf.org/doc/html/rfc8693#section-1.1,
			// we require a principal to be available via the subject_token for
			// impersonation or delegation use cases.
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		// As per https://datatracker.ietf.org/doc/html/rfc8693#section-4.4,
		// The may_act claim makes a statement that one party is authorized to
		// become the actor and act on behalf of another party.
		String authorizedActorSubject = null;
		if (subjectToken.getClaims() != null &&
				subjectToken.getClaims().containsKey(MAY_ACT) &&
				subjectToken.getClaims().get(MAY_ACT) instanceof Map<?, ?> mayAct) {
			authorizedActorSubject = (String) mayAct.get(StandardClaimNames.SUB);
		}

		OAuth2Authorization actorAuthorization = null;
		if (StringUtils.hasText(tokenExchangeAuthentication.getActorToken())) {
			actorAuthorization = this.authorizationService.findByToken(
					tokenExchangeAuthentication.getActorToken(), OAuth2TokenType.ACCESS_TOKEN);
			if (actorAuthorization == null) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
			}

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Retrieved authorization with actor token");
			}

			OAuth2Authorization.Token<OAuth2Token> actorToken = actorAuthorization.getToken(
					tokenExchangeAuthentication.getActorToken());
			if (!actorToken.isActive()) {
				// As per https://tools.ietf.org/html/rfc6749#section-5.2
				// invalid_grant: The provided authorization grant (e.g., authorization code,
				// resource owner credentials) or refresh token is invalid, expired, revoked [...].
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
			}

			if (JWT_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getActorTokenType()) &&
					!Jwt.class.isAssignableFrom(actorToken.getToken().getClass())) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
			}

			if (StringUtils.hasText(authorizedActorSubject) &&
					!authorizedActorSubject.equals(actorAuthorization.getPrincipalName())) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
			}
		} else if (StringUtils.hasText(authorizedActorSubject) &&
				!authorizedActorSubject.equals(clientPrincipal.getName())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		Set<String> authorizedScopes = Collections.emptySet();
		if (!CollectionUtils.isEmpty(tokenExchangeAuthentication.getScopes())) {
			authorizedScopes = validateRequestedScopes(registeredClient, tokenExchangeAuthentication.getScopes());
		} else if (!CollectionUtils.isEmpty(subjectAuthorization.getAuthorizedScopes())) {
			authorizedScopes = validateRequestedScopes(registeredClient, subjectAuthorization.getAuthorizedScopes());
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated token request parameters");
		}

		Authentication principal = getPrincipal(subjectAuthorization, actorAuthorization);

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.authorization(subjectAuthorization)
				.principal(principal)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(TOKEN_EXCHANGE)
				.authorizationGrant(tokenExchangeAuthentication);
		// @formatter:on

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated access token");
		}

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(subjectAuthorization.getPrincipalName())
				.authorizationGrantType(TOKEN_EXCHANGE)
				.authorizedScopes(authorizedScopes)
				.attribute(Principal.class.getName(), principal);
		// @formatter:on

		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken, (metadata) -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims());
				metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
			});
		} else {
			authorizationBuilder.accessToken(accessToken);
		}

		OAuth2Authorization authorization = authorizationBuilder.build();
		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(ISSUED_TOKEN_TYPE, tokenExchangeAuthentication.getRequestedTokenType());

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated token request");
		}

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, null, additionalParameters);
	}

	private static Set<String> validateRequestedScopes(RegisteredClient registeredClient, Set<String> requestedScopes) {
		for (String requestedScope : requestedScopes) {
			if (!registeredClient.getScopes().contains(requestedScope)) {
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
			}
		}

		return new LinkedHashSet<>(requestedScopes);
	}

	private static Authentication getPrincipal(OAuth2Authorization subjectAuthorization, OAuth2Authorization actorAuthorization) {
		Authentication subjectPrincipal = subjectAuthorization.getAttribute(Principal.class.getName());

		List<Authentication> actorPrincipals = new LinkedList<>();
		if (actorAuthorization != null) {
			actorPrincipals.add(new OAuth2ActorAuthenticationToken(actorAuthorization.getPrincipalName()));
		}

		if (subjectPrincipal instanceof OAuth2CompositeAuthenticationToken compositeAuthenticationToken) {
			// As per https://datatracker.ietf.org/doc/html/rfc8693#section-4.1,
			// the act claim can be used to represent a chain of delegation,
			// so we unwrap the original subject and any previous actor(s).
			subjectPrincipal = compositeAuthenticationToken.getSubject();
			actorPrincipals.addAll(compositeAuthenticationToken.getActors());
			// TODO: Should we allow delegation-to-impersonation where previous
			//  actors exist but no actor_token exists on this request?
		}

		return CollectionUtils.isEmpty(actorPrincipals) ? subjectPrincipal :
				new OAuth2CompositeAuthenticationToken(subjectPrincipal, actorPrincipals);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenExchangeAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
