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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an {@link OAuth2AuthorizationCodeAuthenticationToken} and additional information
 * and is used when validating the OAuth 2.0 Token Request parameters used in the Authorization Code Grant.
 *
 * @author neochae
 * @see OAuth2AuthenticationContext
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2AuthorizationCodeAuthenticationContext implements OAuth2AuthenticationContext {
	private final Map<Object, Object> context;

	private OAuth2AuthorizationCodeAuthenticationContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 *
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	@SuppressWarnings("unchecked")
	/**
	 * Returns the {@link OAuth2AuthorizationCode authorizationCode}.
	 *
	 * @return the {@link Token} of type {@link OAuth2AuthorizationCode}
	 */
	public OAuth2Authorization.Token<OAuth2AuthorizationCode> getAuthorizationCode() {
		return get(OAuth2Authorization.Token.class);
	}

	/**
	 * Returns the {@link OAuth2AuthorizationRequest authorization request}.
	 *
	 * @return the {@link OAuth2AuthorizationRequest}
	 */
	public OAuth2AuthorizationRequest getAuthorizationRequest() {
		return get(OAuth2AuthorizationRequest.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided {@link OAuth2AuthorizationCodeAuthenticationToken}.
	 *
	 * @param authentication the {@link OAuth2AuthorizationCodeAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2AuthorizationCodeAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationCodeAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2AuthorizationCodeAuthenticationContext, Builder> {

		private Builder(OAuth2AuthorizationCodeAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link RegisteredClient registered client}.
		 *
		 * @param registeredClient the {@link RegisteredClient}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder registeredClient(RegisteredClient registeredClient) {
			return put(RegisteredClient.class, registeredClient);
		}

		/**
		 * Sets the {@link OAuth2AuthorizationCode authorization code}.
		 *
		 * @param authorizationCode the {@link Token} of type {@link OAuth2AuthorizationCode}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationCode(OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode) {
			return put(OAuth2Authorization.Token.class, authorizationCode);
		}

		/**
		 * Sets the {@link OAuth2AuthorizationRequest authorization request}.
		 *
		 * @param authorizationRequest the {@link OAuth2AuthorizationRequest}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
			return put(OAuth2AuthorizationRequest.class, authorizationRequest);
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationCodeAuthenticationContext}.
		 *
		 * @return the {@link OAuth2AuthorizationCodeAuthenticationContext}
		 */
		public OAuth2AuthorizationCodeAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			return new OAuth2AuthorizationCodeAuthenticationContext(getContext());
		}
	}

}
