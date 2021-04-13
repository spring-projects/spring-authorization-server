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
package org.springframework.security.oauth2.server.authorization.oidc;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/**
 * A {@code Filter} that processes OpenID User Info requests.
 *
 * @author Ido Salomon
 * @see OidcProviderConfiguration
 * @see ProviderSettings
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">5.3.1. UserInfo Request</a>
 * @since 0.1.1
 */
public class OidcUserInfoEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for OpenID User Info requests.
	 */
	public static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";

	private final RequestMatcher requestMatcher;
	private final OidcUserInfoHttpMessageConverter oidcUserInfoHttpMessageConverter =
			new OidcUserInfoHttpMessageConverter();
	private final UserInfoClaimsMapper userInfoClaimsMapper;

	public OidcUserInfoEndpointFilter(UserInfoClaimsMapper userInfoClaimsMapper) {
		AntPathRequestMatcher userInfoGetMatcher = new AntPathRequestMatcher(
				DEFAULT_OIDC_USER_INFO_ENDPOINT_URI,
				HttpMethod.GET.name()
		);
		AntPathRequestMatcher userInfoPostMatcher = new AntPathRequestMatcher(
				DEFAULT_OIDC_USER_INFO_ENDPOINT_URI,
				HttpMethod.POST.name()
		);
		this.requestMatcher = new OrRequestMatcher(userInfoGetMatcher, userInfoPostMatcher);
		this.userInfoClaimsMapper = userInfoClaimsMapper;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Object authenticationDetails = authentication.getDetails();

		Set<String> accessTokenScopes = new HashSet<>();
		if (authenticationDetails instanceof OAuth2AccessToken) {
			accessTokenScopes = ((OAuth2AccessToken) authenticationDetails).getScopes();
		}

		Set<String> OidcScopeValues  = new HashSet<>(Arrays.asList(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, OidcScopes.ADDRESS, OidcScopes.PHONE));
		Set<String> accessTolenOidcScopes = accessTokenScopes.stream()
				.filter(OidcScopeValues::contains)
				.collect(toSet());
		// Set<OidcScopes> = convert...

		Object principal = authentication.getPrincipal();
		OidcUserInfo userInfo = new OidcUserInfo(userInfoClaimsMapper.map(principal));


		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.oidcUserInfoHttpMessageConverter.write(
				userInfo, MediaType.APPLICATION_JSON, httpResponse);
	}

}
