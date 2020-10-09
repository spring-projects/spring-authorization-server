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
package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link Converter} that selects (and delegates) to one of the internal {@code Map} of {@link Converter}'s
 * using the {@link OAuth2ParameterNames#GRANT_TYPE} request parameter.
 *
 * @author Alexey Nesterov
 * @since 0.0.1
 */
public final class DelegatingAuthorizationGrantAuthenticationConverter implements Converter<HttpServletRequest, Authentication> {
	private final Map<AuthorizationGrantType, Converter<HttpServletRequest, Authentication>> converters;

	/**
	 * Constructs a {@code DelegatingAuthorizationGrantAuthenticationConverter} using the provided parameters.
	 *
	 * @param converters a {@code Map} of {@link Converter}(s)
	 */
	public DelegatingAuthorizationGrantAuthenticationConverter(
			Map<AuthorizationGrantType, Converter<HttpServletRequest, Authentication>> converters) {
		Assert.notEmpty(converters, "converters cannot be empty");
		this.converters = Collections.unmodifiableMap(new HashMap<>(converters));
	}

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");

		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (StringUtils.isEmpty(grantType)) {
			return null;
		}

		Converter<HttpServletRequest, Authentication> converter =
				this.converters.get(new AuthorizationGrantType(grantType));
		if (converter == null) {
			return null;
		}

		return converter.convert(request);
	}
}
