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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.io.IOException;
import java.util.function.Supplier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} that associates the {@link AuthorizationServerContext} to the {@link AuthorizationServerContextHolder}.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerContext
 * @see AuthorizationServerContextHolder
 * @see AuthorizationServerSettings
 */
final class AuthorizationServerContextFilter extends OncePerRequestFilter {
	private final AuthorizationServerSettings authorizationServerSettings;

	AuthorizationServerContextFilter(AuthorizationServerSettings authorizationServerSettings) {
		Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
		this.authorizationServerSettings = authorizationServerSettings;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			AuthorizationServerContext authorizationServerContext =
					new DefaultAuthorizationServerContext(
							() -> resolveIssuer(this.authorizationServerSettings, request),
							this.authorizationServerSettings);
			AuthorizationServerContextHolder.setContext(authorizationServerContext);
			filterChain.doFilter(request, response);
		} finally {
			AuthorizationServerContextHolder.resetContext();
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

	private static final class DefaultAuthorizationServerContext implements AuthorizationServerContext {
		private final Supplier<String> issuerSupplier;
		private final AuthorizationServerSettings authorizationServerSettings;

		private DefaultAuthorizationServerContext(Supplier<String> issuerSupplier, AuthorizationServerSettings authorizationServerSettings) {
			this.issuerSupplier = issuerSupplier;
			this.authorizationServerSettings = authorizationServerSettings;
		}

		@Override
		public String getIssuer() {
			return this.issuerSupplier.get();
		}

		@Override
		public AuthorizationServerSettings getAuthorizationServerSettings() {
			return this.authorizationServerSettings;
		}

	}

}
