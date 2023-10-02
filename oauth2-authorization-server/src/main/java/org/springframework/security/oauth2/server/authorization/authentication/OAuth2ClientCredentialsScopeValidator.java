package org.springframework.security.oauth2.server.authorization.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class OAuth2ClientCredentialsScopeValidator {
	private final Log logger = LogFactory.getLog(getClass());

	public Set<String> validateScopes(Set<String> requestedScopes,
			OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication,
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
