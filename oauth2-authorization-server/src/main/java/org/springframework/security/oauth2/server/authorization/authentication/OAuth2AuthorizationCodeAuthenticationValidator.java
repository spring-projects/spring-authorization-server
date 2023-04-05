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

import java.util.function.Consumer;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.util.StringUtils;

/**
 * A {@code Consumer} providing access to the {@link OAuth2AuthorizationCodeAuthenticationContext}
 * containing an {@link OAuth2AuthorizationCodeAuthenticationToken} and {@link OAuth2AuthorizationRequest}
 * and is the default {@link OAuth2AuthorizationCodeAuthenticationProvider#setAuthenticationValidator(Consumer) authentication validator}
 * used for validating specific OAuth 2.0 Token Request parameters used in the Authorization Code Grant.
 *
 * <p>
 * The default implementation first validates {@link OAuth2AuthorizationCodeAuthenticationToken#getRedirectUri()}
 * and then {@link Token<OAuth2AuthorizationCode>#isActive()}.
 * If validation fails, an {@link OAuth2AuthenticationException} is thrown.
 *
 * @author neochae
 * @see OAuth2AuthorizationCodeAuthenticationContext
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2AuthorizationCodeAuthenticationValidator implements Consumer<OAuth2AuthorizationCodeAuthenticationContext> {

	public static final Consumer<OAuth2AuthorizationCodeAuthenticationContext> DEFAULT_REDIRECT_URI_VALIDATOR =
			OAuth2AuthorizationCodeAuthenticationValidator::validateRedirectUri;

	public static final Consumer<OAuth2AuthorizationCodeAuthenticationContext> DEFAULT_AUTHORIZATION_CODE_VALIDATOR =
			OAuth2AuthorizationCodeAuthenticationValidator::validateAuthorizationCode;

	private final Consumer<OAuth2AuthorizationCodeAuthenticationContext> authenticationValidator =
			DEFAULT_REDIRECT_URI_VALIDATOR.andThen(DEFAULT_AUTHORIZATION_CODE_VALIDATOR);

	@Override
	public void accept(OAuth2AuthorizationCodeAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validateRedirectUri(OAuth2AuthorizationCodeAuthenticationContext authenticationContext) {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = authenticationContext.getAuthentication();
		OAuth2AuthorizationRequest authorizationRequest = authenticationContext.getAuthorizationRequest();

		if (StringUtils.hasText(authorizationRequest.getRedirectUri()) &&
				!authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}
	}

	private static void validateAuthorizationCode(OAuth2AuthorizationCodeAuthenticationContext authenticationContext) {
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authenticationContext.getAuthorizationCode();
		if (!authorizationCode.isActive()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}
	}
}
