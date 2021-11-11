/*
 * Copyright 2020-2021 the original author or authors.
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

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an {@link OAuth2AuthorizationConsent.Builder} and additional information
 * and is used when customizing the building of the {@link OAuth2AuthorizationConsent}.
 *
 * @author Steve Riesenberg
 * @author Joe Grandja
 * @since 0.2.1
 * @see OAuth2AuthenticationContext
 * @see OAuth2AuthorizationConsent
 */
public final class OAuth2AuthorizationConsentAuthenticationContext extends OAuth2AuthenticationContext {

	private OAuth2AuthorizationConsentAuthenticationContext(Map<Object, Object> context) {
		super(context);
	}

	/**
	 * Returns the {@link OAuth2AuthorizationConsent.Builder authorization consent builder}.
	 *
	 * @return the {@link OAuth2AuthorizationConsent.Builder}
	 */
	public OAuth2AuthorizationConsent.Builder getAuthorizationConsent() {
		return get(OAuth2AuthorizationConsent.Builder.class);
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 *
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	/**
	 * Returns the {@link OAuth2Authorization authorization}.
	 *
	 * @return the {@link OAuth2Authorization}
	 */
	public OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
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
	 * Constructs a new {@link Builder} with the provided {@link Authentication} and {@link OAuth2AuthorizationConsent.Builder}.
	 *
	 * @param authentication the {@link Authentication}
	 * @param authorizationConsentBuilder the {@link OAuth2AuthorizationConsent.Builder}
	 * @return the {@link Builder}
	 */
	public static Builder with(Authentication authentication, OAuth2AuthorizationConsent.Builder authorizationConsentBuilder) {
		return new Builder(authentication, authorizationConsentBuilder);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationConsentAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2AuthorizationConsentAuthenticationContext, Builder> {

		private Builder(Authentication authentication, OAuth2AuthorizationConsent.Builder authorizationConsentBuilder) {
			super(authentication);
			Assert.notNull(authorizationConsentBuilder, "authorizationConsentBuilder cannot be null");
			put(OAuth2AuthorizationConsent.Builder.class, authorizationConsentBuilder);
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
		 * Sets the {@link OAuth2Authorization authorization}.
		 *
		 * @param authorization the {@link OAuth2Authorization}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
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
		 * Builds a new {@link OAuth2AuthorizationConsentAuthenticationContext}.
		 *
		 * @return the {@link OAuth2AuthorizationConsentAuthenticationContext}
		 */
		public OAuth2AuthorizationConsentAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			Assert.notNull(get(OAuth2Authorization.class), "authorization cannot be null");
			Assert.notNull(get(OAuth2AuthorizationRequest.class), "authorizationRequest cannot be null");
			return new OAuth2AuthorizationConsentAuthenticationContext(getContext());
		}

	}

}
