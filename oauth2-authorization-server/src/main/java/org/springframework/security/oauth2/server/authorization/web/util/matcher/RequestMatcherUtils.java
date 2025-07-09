/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web.util.matcher;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Utility methods for {@link RequestMatcher}.
 *
 * <p>
 * <b>NOTE:</b> This utility is intended for internal use only.
 *
 * @author Joe Grandja
 * @since 2.0
 */
public final class RequestMatcherUtils {

	private RequestMatcherUtils() {
	}

	public static RequestMatcher matcher(String pattern, HttpMethod httpMethod) {
		Assert.hasText(pattern, "pattern cannot be empty");
		Assert.notNull(httpMethod, "httpMethod cannot be null");
		return containsMultipleIssuersPattern(pattern) ? new AntPathRequestMatcher(pattern, httpMethod)
				: PathPatternRequestMatcher.withDefaults().matcher(httpMethod, pattern);
	}

	public static String withMultipleIssuersPattern(String pattern) {
		Assert.hasText(pattern, "pattern cannot be empty");
		return pattern.startsWith("/") ? "/**" + pattern : "/**/" + pattern;
	}

	private static boolean containsMultipleIssuersPattern(String pattern) {
		return pattern.startsWith("/**/");
	}

	private static final class AntPathRequestMatcher implements RequestMatcher {

		private final AntPathMatcher matcher;

		private final String pattern;

		private final HttpMethod httpMethod;

		private AntPathRequestMatcher(String pattern, HttpMethod httpMethod) {
			this.matcher = new AntPathMatcher();
			this.pattern = pattern;
			this.httpMethod = httpMethod;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			if (StringUtils.hasText(request.getMethod())
					&& this.httpMethod != HttpMethod.valueOf(request.getMethod())) {
				return false;
			}
			String requestPath = getRequestPath(request);
			return this.matcher.match(this.pattern, requestPath);
		}

		private static String getRequestPath(HttpServletRequest request) {
			String url = request.getServletPath();
			String pathInfo = request.getPathInfo();
			if (pathInfo != null) {
				url = StringUtils.hasLength(url) ? url + pathInfo : pathInfo;
			}
			return url;
		}

	}

}
