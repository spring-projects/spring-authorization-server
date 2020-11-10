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

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.endpoint.PkceCodeChallengeMethod2;
import org.springframework.security.oauth2.core.http.converter.OAuth2AuthorizationServerConfigurationHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A {@code Filter} that processes OAuth 2.0 Authorization Server Configuration Requests.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.1
 * @see ProviderSettings
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-3">3. Obtaining Authorization Server Metadata</a>
 */
public class OAuth2AuthorizationServerConfigurationEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for OAuth 2.0 Authorization Server Configuration requests.
	 */
	public static final String DEFAULT_OAUTH2_AUTHORIZATION_SERVER_CONFIGURATION_ENDPOINT_URI = "/.well-known/oauth-authorization-server";

	private final RequestMatcher requestMatcher;
	private final ProviderSettings providerSettings;
	private final OAuth2AuthorizationServerConfigurationHttpMessageConverter authorizationServerConfigurationHttpMessageConverter
			= new OAuth2AuthorizationServerConfigurationHttpMessageConverter();

	public OAuth2AuthorizationServerConfigurationEndpointFilter(ProviderSettings providerSettings) {
		Assert.notNull(providerSettings, "providerSettings cannot be null");
		this.providerSettings = providerSettings;
		this.requestMatcher = new AntPathRequestMatcher(
				DEFAULT_OAUTH2_AUTHORIZATION_SERVER_CONFIGURATION_ENDPOINT_URI,
				HttpMethod.GET.name()
		);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		OAuth2AuthorizationServerConfiguration authorizationServerConfiguration = OAuth2AuthorizationServerConfiguration
				.builder()
				.issuer(this.providerSettings.issuer())
				.authorizationEndpoint(asUrl(this.providerSettings.issuer(), this.providerSettings.authorizationEndpoint()))
				.tokenEndpoint(asUrl(this.providerSettings.issuer(), this.providerSettings.tokenEndpoint()))
				.tokenEndpointAuthenticationMethod("client_secret_basic") // TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_BASIC in Spring Security 5.5.0
				.tokenEndpointAuthenticationMethod("client_secret_post") // TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_POST in Spring Security 5.5.0
				.tokenRevocationEndpoint(asUrl(this.providerSettings.issuer(), this.providerSettings.tokenRevocationEndpoint()))
				.tokenRevocationEndpointAuthenticationMethod("client_secret_basic") // TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_BASIC in Spring Security 5.5.0
				.tokenRevocationEndpointAuthenticationMethod("client_secret_post") // TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_POST in Spring Security 5.5.0
				.jwkSetUri(asUrl(this.providerSettings.issuer(), this.providerSettings.jwkSetEndpoint()))
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.grantType(AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
				.scope(OidcScopes.OPENID)
				.codeChallengeMethod(PkceCodeChallengeMethod2.PLAIN.getValue())
				.codeChallengeMethod(PkceCodeChallengeMethod2.S256.getValue())
				.build();

		ServletServerHttpResponse resp = new ServletServerHttpResponse(response);
		this.authorizationServerConfigurationHttpMessageConverter.write(
				authorizationServerConfiguration, MediaType.APPLICATION_JSON, resp);
	}

	private static String asUrl(String issuer, String endpoint) {
		return UriComponentsBuilder.fromUriString(issuer).path(endpoint).toUriString();
	}
}
