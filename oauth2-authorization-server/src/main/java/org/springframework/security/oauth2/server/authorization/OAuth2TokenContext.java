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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.context.Context;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * @author Joe Grandja
 * @since 0.1.0
 * @see Context
 */
public interface OAuth2TokenContext extends Context {

	default RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	default <T extends Authentication> T getPrincipal() {
		return get(AbstractBuilder.PRINCIPAL_AUTHENTICATION_KEY);
	}

	@Nullable
	default OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	default Set<String> getAuthorizedScopes() {
		return hasKey(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME) ?
				get(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME) :
				Collections.emptySet();
	}

	default OAuth2TokenType getTokenType() {
		return get(OAuth2TokenType.class);
	}

	default AuthorizationGrantType getAuthorizationGrantType() {
		return get(AuthorizationGrantType.class);
	}

	default <T extends Authentication> T getAuthorizationGrant() {
		return get(AbstractBuilder.AUTHORIZATION_GRANT_AUTHENTICATION_KEY);
	}

	abstract class AbstractBuilder<T extends OAuth2TokenContext, B extends AbstractBuilder<T, B>> {
		private static final String PRINCIPAL_AUTHENTICATION_KEY =
				Authentication.class.getName().concat(".PRINCIPAL");
		private static final String AUTHORIZATION_GRANT_AUTHENTICATION_KEY =
				Authentication.class.getName().concat(".AUTHORIZATION_GRANT");
		protected final Map<Object, Object> context = new HashMap<>();

		public B registeredClient(RegisteredClient registeredClient) {
			return put(RegisteredClient.class, registeredClient);
		}

		public B principal(Authentication principal) {
			return put(PRINCIPAL_AUTHENTICATION_KEY, principal);
		}

		public B authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
		}

		public B authorizedScopes(Set<String> authorizedScopes) {
			return put(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes);
		}

		public B tokenType(OAuth2TokenType tokenType) {
			return put(OAuth2TokenType.class, tokenType);
		}

		public B authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
			return put(AuthorizationGrantType.class, authorizationGrantType);
		}

		public B authorizationGrant(Authentication authorizationGrant) {
			return put(AUTHORIZATION_GRANT_AUTHENTICATION_KEY, authorizationGrant);
		}

		public B put(Object key, Object value) {
			Assert.notNull(key, "key cannot be null");
			Assert.notNull(value, "value cannot be null");
			this.context.put(key, value);
			return getThis();
		}

		public B context(Consumer<Map<Object, Object>> contextConsumer) {
			contextConsumer.accept(this.context);
			return getThis();
		}

		@SuppressWarnings("unchecked")
		protected <V> V get(Object key) {
			return (V) this.context.get(key);
		}

		@SuppressWarnings("unchecked")
		protected B getThis() {
			return (B) this;
		}

		public abstract T build();

	}
}
