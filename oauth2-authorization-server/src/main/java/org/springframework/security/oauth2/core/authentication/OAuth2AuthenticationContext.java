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
package org.springframework.security.oauth2.core.authentication;

import java.util.HashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.context.Context;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * A context that holds an {@link Authentication} and (optionally) additional information
 * and is used by an {@link OAuth2AuthenticationValidator} when attempting to validate the {@link Authentication}.
 *
 * @author Joe Grandja
 * @since 0.2.0
 * @see Context
 * @see OAuth2AuthenticationValidator
 */
public final class OAuth2AuthenticationContext implements Context {
	private final Map<Object, Object> context;

	/**
	 * Constructs an {@code OAuth2AuthenticationContext} using the provided parameters.
	 *
	 * @param authentication the {@code Authentication}
	 * @param context a {@code Map} of additional context information
	 */
	public OAuth2AuthenticationContext(Authentication authentication, @Nullable Map<Object, Object> context) {
		Assert.notNull(authentication, "authentication cannot be null");
		this.context = new HashMap<>();
		if (!CollectionUtils.isEmpty(context)) {
			this.context.putAll(context);
		}
		this.context.put(Authentication.class, authentication);
	}

	/**
	 * Returns the {@link Authentication} associated to the authentication context.
	 *
	 * @param <T> the type of the {@code Authentication}
	 * @return the {@link Authentication}
	 */
	@SuppressWarnings("unchecked")
	public <T extends Authentication> T getAuthentication() {
		return (T) get(Authentication.class);
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

}
