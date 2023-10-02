/*
 * Copyright 2020-2023 the original author or authors.
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
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Set;
import java.util.function.Consumer;

/**
 * A {@code Consumer} providing access to the {@link OAuth2ClientCredentialsAuthenticationContext}
 * containing an {@link OAuth2ClientCredentialsAuthenticationToken}
 * and is the default {@link OAuth2ClientCredentialsAuthenticationProvider#setAuthenticationValidator(Consumer) authentication validator}
 * used for validating specific OAuth 2.0 Client Credentials parameters used in the Client Credentials Grant.
 *
 * <p>
 * The default compares the provided scopes with those configured in the RegisteredClient.
 * If validation fails, an {@link OAuth2ClientCredentialsAuthenticationException} is thrown.
 *
 * @author Adam Pilling
 * @since 1.3.0
 * @see OAuth2ClientCredentialsAuthenticationContext
 * @see RegisteredClient
 * @see OAuth2ClientCredentialsAuthenticationToken
 * @see OAuth2ClientCredentialsAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2ClientCredentialsAuthenticationValidator implements Consumer<OAuth2ClientCredentialsAuthenticationContext> {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final Log LOGGER = LogFactory.getLog(OAuth2ClientCredentialsAuthenticationValidator.class);

	/**
	 * The default validator for {@link OAuth2ClientCredentialsAuthenticationToken#getScopes()}.
	 */
	public static final Consumer<OAuth2ClientCredentialsAuthenticationContext> DEFAULT_SCOPE_VALIDATOR =
			OAuth2ClientCredentialsAuthenticationValidator::validateScope;

	private final Consumer<OAuth2ClientCredentialsAuthenticationContext> authenticationValidator = DEFAULT_SCOPE_VALIDATOR;

	@Override
	public void accept(OAuth2ClientCredentialsAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validateScope(OAuth2ClientCredentialsAuthenticationContext authenticationContext) {
		OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthenticationToken =
				authenticationContext.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

		Set<String> requestedScopes = clientCredentialsAuthenticationToken.getScopes();
		Set<String> allowedScopes = registeredClient.getScopes();
		if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(LogMessage.format("Invalid request: requested scope is not allowed" +
						" for registered client '%s'", registeredClient.getId()));
			}
			throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE, clientCredentialsAuthenticationToken);
		}
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthenticationToken) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		OAuth2ClientCredentialsAuthenticationToken authorizationCodeRequestAuthenticationResult =
				new OAuth2ClientCredentialsAuthenticationToken(
						(Authentication) clientCredentialsAuthenticationToken.getPrincipal(),
						clientCredentialsAuthenticationToken.getScopes(),
						clientCredentialsAuthenticationToken.getAdditionalParameters());
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);

		throw new OAuth2ClientCredentialsAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
	}

}
