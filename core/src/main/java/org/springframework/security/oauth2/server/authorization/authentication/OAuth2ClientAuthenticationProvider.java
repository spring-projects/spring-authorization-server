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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that validates {@link OAuth2ClientAuthenticationToken}s.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 */
public class OAuth2ClientAuthenticationProvider implements AuthenticationProvider {
	private final RegisteredClientRepository registeredClientRepository;

	/**
	 * @param registeredClientRepository
	 * 		the bean to lookup the client details from
	 */
	public OAuth2ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.registeredClientRepository = registeredClientRepository;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String clientId = authentication.getName();
		if (authentication.getCredentials() == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		// https://tools.ietf.org/html/rfc6749#section-2.4
		if (registeredClient == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		String presentedSecret = authentication.getCredentials()
				.toString();
		if (!registeredClient.getClientSecret()
				.equals(presentedSecret)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
		}

		return new OAuth2ClientAuthenticationToken(registeredClient);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
