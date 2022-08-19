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
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
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
 * @see AuthorizationServerSettings
 */
public final class ProviderContextFilter extends OncePerRequestFilter {
	private final AuthorizationServerSettings authorizationServerSettings;

	/**
	 * Constructs a {@code ProviderContextFilter} using the provided parameters.
	 *
	 * @param authorizationServerSettings the authorization server settings
	 */
	public ProviderContextFilter(AuthorizationServerSettings authorizationServerSettings) {
		Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
		this.authorizationServerSettings = authorizationServerSettings;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			ProviderContext providerContext = new ProviderContext(
					this.authorizationServerSettings, () -> resolveIssuer(this.authorizationServerSettings, request));
			ProviderContextHolder.setProviderContext(providerContext);
			filterChain.doFilter(request, response);
		} finally {
			ProviderContextHolder.resetProviderContext();
		}
	}

	private static String resolveIssuer(AuthorizationServerSettings authorizationServerSettings, HttpServletRequest request) {
		return authorizationServerSettings.getIssuer() != null ?
				authorizationServerSettings.getIssuer() :
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
