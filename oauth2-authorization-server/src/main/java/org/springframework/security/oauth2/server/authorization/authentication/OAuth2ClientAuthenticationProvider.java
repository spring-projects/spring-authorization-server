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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation used for authenticating an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @author Daniel Garnier-Moiroux
 * @author Rafal Lewczuk
 * @since 0.0.1
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see JwtClientAssertionAuthenticationProvider
 * @see ClientSecretAuthenticationProvider
 * @see PublicClientAuthenticationProvider
 * @deprecated This implementation is decomposed into {@link JwtClientAssertionAuthenticationProvider},
 * {@link ClientSecretAuthenticationProvider} and {@link PublicClientAuthenticationProvider}.
 */
@Deprecated
public final class OAuth2ClientAuthenticationProvider implements AuthenticationProvider {
	private static final ClientAuthenticationMethod JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
	private final JwtClientAssertionAuthenticationProvider jwtClientAssertionAuthenticationProvider;
	private final ClientSecretAuthenticationProvider clientSecretAuthenticationProvider;
	private final PublicClientAuthenticationProvider publicClientAuthenticationProvider;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OAuth2ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.jwtClientAssertionAuthenticationProvider = new JwtClientAssertionAuthenticationProvider(
				registeredClientRepository, authorizationService);
		this.clientSecretAuthenticationProvider = new ClientSecretAuthenticationProvider(
				registeredClientRepository, authorizationService);
		this.publicClientAuthenticationProvider = new PublicClientAuthenticationProvider(
				registeredClientRepository, authorizationService);
	}

	/**
	 * Sets the {@link PasswordEncoder} used to validate
	 * the {@link RegisteredClient#getClientSecret() client secret}.
	 * If not set, the client secret will be compared using
	 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.
	 *
	 * @param passwordEncoder the {@link PasswordEncoder} used to validate the client secret
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.clientSecretAuthenticationProvider.setPasswordEncoder(passwordEncoder);
	}

	@Autowired
	protected void setProviderSettings(ProviderSettings providerSettings) {
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		if (JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return this.jwtClientAssertionAuthenticationProvider.authenticate(authentication);
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientAuthentication.getClientAuthenticationMethod()) ||
				ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return this.clientSecretAuthenticationProvider.authenticate(authentication);
		} else {
			return this.publicClientAuthenticationProvider.authenticate(authentication);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
