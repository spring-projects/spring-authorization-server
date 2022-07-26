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
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.context.Context;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * A context that holds an {@link Authentication} and (optionally) additional information.
 *
 * @author Joe Grandja
 * @since 0.2.0
 * @see Context
 */
public class OAuth2AuthenticationContext implements Context {
	private final Map<Object, Object> context;

	/**
	 * Constructs an {@code OAuth2AuthenticationContext} using the provided parameters.
	 *
	 * @param authentication the {@code Authentication}
	 * @param context a {@code Map} of additional context information
	 */
	public OAuth2AuthenticationContext(Authentication authentication, @Nullable Map<Object, Object> context) {
		Assert.notNull(authentication, "authentication cannot be null");
		Map<Object, Object> ctx = new HashMap<>();
		if (!CollectionUtils.isEmpty(context)) {
			ctx.putAll(context);
		}
		ctx.put(Authentication.class, authentication);
		this.context = Collections.unmodifiableMap(ctx);
	}

	/**
	 * Constructs an {@code OAuth2AuthenticationContext} using the provided parameters.
	 *
	 * @param context a {@code Map} of context information, must contain the {@code Authentication}
	 * @since 0.2.1
	 */
	public OAuth2AuthenticationContext(Map<Object, Object> context) {
		Assert.notEmpty(context, "context cannot be empty");
		Assert.notNull(context.get(Authentication.class), "authentication cannot be null");
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	/**
	 * Returns the {@link Authentication} associated to the context.
	 *
	 * @param <T> the type of the {@code Authentication}
	 * @return the {@link Authentication}
	 */
	@SuppressWarnings("unchecked")
	public <T extends Authentication> T getAuthentication() {
		return (T) get(Authentication.class);
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
	 * A builder for subclasses of {@link OAuth2AuthenticationContext}.
	 *
	 * @param <T> the type of the authentication context
	 * @param <B> the type of the builder
	 * @since 0.2.1
	 */
	protected static abstract class AbstractBuilder<T extends OAuth2AuthenticationContext, B extends AbstractBuilder<T, B>> {
		private final Map<Object, Object> context = new HashMap<>();

		protected AbstractBuilder(Authentication authentication) {
			Assert.notNull(authentication, "authentication cannot be null");
			put(Authentication.class, authentication);
		}

		/**
		 * Associates an attribute.
		 *
		 * @param key the key for the attribute
		 * @param value the value of the attribute
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B put(Object key, Object value) {
			Assert.notNull(key, "key cannot be null");
			Assert.notNull(value, "value cannot be null");
			getContext().put(key, value);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the attributes {@code Map}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param contextConsumer a {@link Consumer} of the attributes {@code Map}
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B context(Consumer<Map<Object, Object>> contextConsumer) {
			contextConsumer.accept(getContext());
			return getThis();
		}

		@SuppressWarnings("unchecked")
		protected <V> V get(Object key) {
			return (V) getContext().get(key);
		}

		protected Map<Object, Object> getContext() {
			return this.context;
		}

		@SuppressWarnings("unchecked")
		protected final B getThis() {
			return (B) this;
		}

		/**
		 * Builds a new {@link OAuth2AuthenticationContext}.
		 *
		 * @return the {@link OAuth2AuthenticationContext}
		 */
		public abstract T build();

	}

}
