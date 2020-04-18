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

package sample;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

import com.nimbusds.jose.jwk.JWKSet;

public class JwkSetEndpointFilter extends OncePerRequestFilter {

	static final String WELL_KNOWN_JWK_URIS = "/.well-known/jwk_uris";

	private final RequestMatcher requestMatcher = new AntPathRequestMatcher(WELL_KNOWN_JWK_URIS, GET.name(), true,
			new UrlPathHelper());

	private final JWKSet jwkSet;

	public JwkSetEndpointFilter(JWKSet jwkSet) {
		Assert.notNull(jwkSet, "jwkSet cannot be null");
		this.jwkSet = jwkSet;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (ifRequestMatches(request)) {
			respond(response);
		} else {
			filterChain.doFilter(request, response);
		}
	}

	private void respond(HttpServletResponse response) throws IOException {
		response.setContentType(APPLICATION_JSON_VALUE);
		try (Writer writer = response.getWriter()) {
			writer.write(jwkSet.toPublicJWKSet().toJSONObject().toJSONString());
		}
	}

	private boolean ifRequestMatches(HttpServletRequest request) {
		return this.requestMatcher.matches(request);
	}

}
