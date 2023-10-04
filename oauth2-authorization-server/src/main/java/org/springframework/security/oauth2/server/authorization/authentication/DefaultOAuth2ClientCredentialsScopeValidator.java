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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class DefaultOAuth2ClientCredentialsScopeValidator implements OAuth2ClientCredentialsScopeValidator {
	private final Log logger = LogFactory.getLog(getClass());

	public Set<String> validateScopes(OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication,
			OAuth2ClientAuthenticationToken clientPrincipal) {
		Set<String> authorizedScopes = Collections.emptySet();
		if (!CollectionUtils.isEmpty(clientCredentialsAuthentication.getScopes())) {
			for (String requestedScope : clientCredentialsAuthentication.getScopes()) {
				if (!clientPrincipal.getRegisteredClient().getScopes().contains(requestedScope)) {
					throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
				}
			}
			authorizedScopes = new LinkedHashSet<>(clientCredentialsAuthentication.getScopes());
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated scopes");
		}

		return authorizedScopes;
	}
}
