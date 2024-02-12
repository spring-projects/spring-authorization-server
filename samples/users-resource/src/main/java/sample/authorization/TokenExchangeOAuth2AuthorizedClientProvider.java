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
package sample.authorization;

import java.time.Clock;
import java.time.Duration;
import java.util.function.Function;

import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
public final class TokenExchangeOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

	private OAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient = new DefaultTokenExchangeTokenResponseClient();

	private Function<OAuth2AuthorizationContext, String> subjectTokenResolver = this::resolveSubjectToken;

	private Function<OAuth2AuthorizationContext, String> actorTokenResolver = (context) -> null;

	private Duration clockSkew = Duration.ofSeconds(60);

	private Clock clock = Clock.systemUTC();

	@Override
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		ClientRegistration clientRegistration = context.getClientRegistration();
		if (!TokenExchangeGrantRequest.TOKEN_EXCHANGE.equals(clientRegistration.getAuthorizationGrantType())) {
			return null;
		}
		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
		if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
			// If client is already authorized but access token is NOT expired than no
			// need for re-authorization
			return null;
		}
		if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {
			// If client is already authorized but access token is expired and a
			// refresh token is available, delegate to refresh_token.
			return null;
		}

		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration,
				this.subjectTokenResolver.apply(context), this.actorTokenResolver.apply(context));
		OAuth2AccessTokenResponse tokenResponse = getTokenResponse(clientRegistration, grantRequest);

		return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
				tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
	}

	private OAuth2AccessTokenResponse getTokenResponse(ClientRegistration clientRegistration,
			TokenExchangeGrantRequest grantRequest) {
		try {
			return this.accessTokenResponseClient.getTokenResponse(grantRequest);
		} catch (OAuth2AuthorizationException ex) {
			throw new ClientAuthorizationException(ex.getError(), clientRegistration.getRegistrationId(), ex);
		}
	}

	private boolean hasTokenExpired(OAuth2Token token) {
		return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
	}

	private String resolveSubjectToken(OAuth2AuthorizationContext context) {
		if (context.getPrincipal().getPrincipal() instanceof OAuth2Token accessToken) {
			return accessToken.getTokenValue();
		}
		return null;
	}

	public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<TokenExchangeGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	public void setSubjectTokenResolver(Function<OAuth2AuthorizationContext, String> subjectTokenResolver) {
		Assert.notNull(subjectTokenResolver, "subjectTokenResolver cannot be null");
		this.subjectTokenResolver = subjectTokenResolver;
	}

	public void setActorTokenResolver(Function<OAuth2AuthorizationContext, String> actorTokenResolver) {
		Assert.notNull(actorTokenResolver, "actorTokenResolver cannot be null");
		this.actorTokenResolver = actorTokenResolver;
	}

	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		this.clockSkew = clockSkew;
	}

	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

}
