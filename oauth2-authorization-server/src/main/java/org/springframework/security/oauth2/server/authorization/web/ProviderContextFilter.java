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
package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} that associates the {@link ProviderContext} to the {@link ProviderContextHolder}.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see ProviderContext
 * @see ProviderContextHolder
 * @see ProviderSettings
 */
public final class ProviderContextFilter extends OncePerRequestFilter {
	private final ProviderSettings providerSettings;

	/**
	 * Constructs a {@code ProviderContextFilter} using the provided parameters.
	 *
	 * @param providerSettings the provider settings
	 */
	public ProviderContextFilter(ProviderSettings providerSettings) {
		Assert.notNull(providerSettings, "providerSettings cannot be null");
		this.providerSettings = providerSettings;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			ProviderContext providerContext = new ProviderContext(
					this.providerSettings, () -> resolveIssuer(this.providerSettings, request));
			ProviderContextHolder.setProviderContext(providerContext);
			filterChain.doFilter(request, response);
		} finally {
			ProviderContextHolder.resetProviderContext();
		}
	}

	private static String resolveIssuer(ProviderSettings providerSettings, HttpServletRequest request) {
		return providerSettings.getIssuer() != null ?
				providerSettings.getIssuer() :
				getContextPath(request);
	}

	private static String getContextPath(HttpServletRequest request) {
		// @formatter:off
		return UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build()
				.toUriString();
		// @formatter:on
	}

}
