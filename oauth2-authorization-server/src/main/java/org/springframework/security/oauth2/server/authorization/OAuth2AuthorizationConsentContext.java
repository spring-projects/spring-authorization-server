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
package org.springframework.security.oauth2.server.authorization;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.context.Context;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * A context that holds an {@link OAuth2AuthorizationConsent.Builder} and (optionally) additional information
 * and is used when customizing the building of {@link OAuth2AuthorizationConsent}.
 *
 * @author Steve Riesenberg
 * @since 0.2.1
 * @see Context
 */
public final class OAuth2AuthorizationConsentContext implements Context {
	private final Map<Object, Object> context;

	/**
	 * Constructs an {@code OAuth2AuthorizationConsentContext} using the provided parameters.
	 *
	 * @param context a {@code Map} of additional context information
	 */
	private OAuth2AuthorizationConsentContext(@Nullable Map<Object, Object> context) {
		this.context = new HashMap<>();
		if (!CollectionUtils.isEmpty(context)) {
			this.context.putAll(context);
		}
	}

	/**
	 * Returns the {@link OAuth2AuthorizationConsent.Builder authorization consent builder}.
	 *
	 * @return the {@link OAuth2AuthorizationConsent.Builder}
	 */
	public OAuth2AuthorizationConsent.Builder getAuthorizationConsentBuilder() {
		return get(OAuth2AuthorizationConsent.Builder.class);
	}

	/**
	 * Returns the {@link Authentication} representing the {@code Principal} resource owner (or client).
	 *
	 * @param <T> the type of the {@code Authentication}
	 * @return the {@link Authentication} representing the {@code Principal} resource owner (or client)
	 */
	@Nullable
	public <T extends Authentication> T getPrincipal() {
		return get(Builder.PRINCIPAL_AUTHENTICATION_KEY);
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 *
	 * @return the {@link RegisteredClient}, or {@code null} if not available
	 */
	@Nullable
	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	/**
	 * Returns the {@link OAuth2Authorization authorization}.
	 *
	 * @return the {@link OAuth2Authorization}, or {@code null} if not available
	 */
	@Nullable
	public OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	/**
	 * Returns the {@link OAuth2AuthorizationRequest authorization request}.
	 *
	 * @return the {@link OAuth2AuthorizationRequest}, or {@code null} if not available
	 */
	@Nullable
	public OAuth2AuthorizationRequest getAuthorizationRequest() {
		return get(OAuth2AuthorizationRequest.class);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <V> V get(Object key) {
		return (V) this.context.get(key);
	}

	@Override
	public boolean hasKey(Object key) {
		return this.context.containsKey(key);
	}

	/**
	 * Constructs a new {@link Builder} with the provided {@link OAuth2AuthorizationConsent.Builder}.
	 *
	 * @param authorizationConsentBuilder the {@link OAuth2AuthorizationConsent.Builder} to initialize the builder
	 * @return the {@link Builder}
	 */
	public static OAuth2AuthorizationConsentContext.Builder with(OAuth2AuthorizationConsent.Builder authorizationConsentBuilder) {
		return new Builder(authorizationConsentBuilder);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationConsentContext}.
	 */
	public static final class Builder {
		private static final String PRINCIPAL_AUTHENTICATION_KEY =
				Authentication.class.getName().concat(".PRINCIPAL");
		private final Map<Object, Object> context = new HashMap<>();

		private Builder(OAuth2AuthorizationConsent.Builder authorizationConsentBuilder) {
			Assert.notNull(authorizationConsentBuilder, "authorizationConsentBuilder cannot be null");
			put(OAuth2AuthorizationConsent.Builder.class, authorizationConsentBuilder);
		}

		/**
		 * Sets the {@link Authentication} representing the {@code Principal} resource owner (or client).
		 *
		 * @param principal the {@link Authentication} representing the {@code Principal} resource owner (or client)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder principal(Authentication principal) {
			return put(PRINCIPAL_AUTHENTICATION_KEY, principal);
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
		 * Associates an attribute.
		 *
		 * @param key the key for the attribute
		 * @param value the value of the attribute
		 * @return the {@link OAuth2TokenContext.AbstractBuilder} for further configuration
		 */
		public Builder put(Object key, Object value) {
			Assert.notNull(key, "key cannot be null");
			Assert.notNull(value, "value cannot be null");
			this.context.put(key, value);
			return this;
		}

		/**
		 * A {@code Consumer} of the attributes {@code Map}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param contextConsumer a {@link Consumer} of the attributes {@code Map}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder context(Consumer<Map<Object, Object>> contextConsumer) {
			contextConsumer.accept(this.context);
			return this;
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationConsentContext}.
		 *
		 * @return the {@link OAuth2AuthorizationConsentContext}
		 */
		public OAuth2AuthorizationConsentContext build() {
			return new OAuth2AuthorizationConsentContext(this.context);
		}
	}
}
