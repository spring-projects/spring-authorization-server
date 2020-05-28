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
package org.springframework.security.oauth2.server.authorization;

import org.springframework.util.Assert;

/**
 * An {@link OAuth2TokenRevocationService} that revokes tokens.
 *
 * @author Vivek Babu
 * @see OAuth2AuthorizationService
 * @since 0.0.1
 */
public final class DefaultOAuth2TokenRevocationService implements OAuth2TokenRevocationService {

	private OAuth2AuthorizationService authorizationService;

	/**
	 * Constructs an {@code DefaultOAuth2TokenRevocationService}.
	 */
	public DefaultOAuth2TokenRevocationService(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public void revoke(String token, TokenType tokenType) {
		final OAuth2Authorization authorization = this.authorizationService.findByTokenAndTokenType(token, tokenType);
		if (authorization != null) {
			final OAuth2Authorization revokedAuthorization = OAuth2Authorization.from(authorization)
					.revoked(true).build();
			this.authorizationService.save(revokedAuthorization);
		}
	}
}
