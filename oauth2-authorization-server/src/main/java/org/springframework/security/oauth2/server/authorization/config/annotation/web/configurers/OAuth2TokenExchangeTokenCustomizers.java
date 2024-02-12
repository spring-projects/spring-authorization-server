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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2CompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.CollectionUtils;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
final class OAuth2TokenExchangeTokenCustomizers {

	private static final AuthorizationGrantType TOKEN_EXCHANGE = new AuthorizationGrantType(
			"urn:ietf:params:oauth:grant-type:token-exchange");

	private OAuth2TokenExchangeTokenCustomizers() {
	}

	static OAuth2TokenCustomizer<JwtEncodingContext> jwt() {
		return (context) -> context.getClaims().claims((claims) -> customize(context, claims));
	}

	static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessToken() {
		return (context) -> context.getClaims().claims((claims) -> customize(context, claims));
	}

	private static void customize(OAuth2TokenContext context, Map<String, Object> claims) {
		if (!TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
			return;
		}

		if (context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication) {
			// Customize the token claims when audience is present in the request
			List<String> audience = tokenExchangeAuthentication.getAudiences();
			if (!CollectionUtils.isEmpty(audience)) {
				claims.put(OAuth2TokenClaimNames.AUD, audience);
			}
		}

		// As per https://datatracker.ietf.org/doc/html/rfc8693#section-4.1,
		// we handle a composite principal with an actor by adding an "act"
		// claim with a "sub" claim of the actor.
		//
		// If more than one actor is present, we create a chain of delegation by
		// nesting "act" claims.
		if (context.getPrincipal() instanceof OAuth2CompositeAuthenticationToken compositeAuthenticationToken) {
			Map<String, Object> currentClaims = claims;
			for (Authentication actorPrincipal : compositeAuthenticationToken.getActors()) {
				Map<String, Object> actClaim = new HashMap<>();
				actClaim.put("sub", actorPrincipal.getName());
				currentClaims.put("act", Collections.unmodifiableMap(actClaim));
				currentClaims = actClaim;
			}
		}
	}

}
