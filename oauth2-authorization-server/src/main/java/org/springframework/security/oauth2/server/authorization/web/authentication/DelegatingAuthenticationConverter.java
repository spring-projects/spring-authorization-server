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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that simply delegates to it's internal {@code List}
 * of {@link AuthenticationConverter}(s).
 * <p>
 * Each {@link AuthenticationConverter} is given a chance to
 * {@link AuthenticationConverter#convert(HttpServletRequest)} with the first
 * {@code non-null} {@link Authentication} being returned.
 *
 * @author Joe Grandja
 * @since 0.0.2
 * @see AuthenticationConverter
 */
public final class DelegatingAuthenticationConverter implements AuthenticationConverter {

	private final List<AuthenticationConverter> converters;

	/**
	 * Constructs a {@code DelegatingAuthenticationConverter} using the provided
	 * parameters.
	 * @param converters a {@code List} of {@link AuthenticationConverter}(s)
	 */
	public DelegatingAuthenticationConverter(List<AuthenticationConverter> converters) {
		Assert.notEmpty(converters, "converters cannot be empty");
		this.converters = Collections.unmodifiableList(new LinkedList<>(converters));
	}

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		for (AuthenticationConverter converter : this.converters) {
			Authentication authentication = converter.convert(request);
			if (authentication != null) {
				return authentication;
			}
		}
		return null;
	}

}
