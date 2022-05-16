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
package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.DefaultOAuth2ConsentPageHandler;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ConsentHandler;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Authorization Request (and Consent).
 *
 * @author Joe Grandja
 * @author Paurav Munshi
 * @author Daniel Garnier-Moiroux
 * @author Anoop Garlapati
 * @author Dmitriy Dubson
 * @since 0.0.1
 * @see AuthenticationManager
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public final class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for authorization requests.
	 */
	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher authorizationEndpointMatcher;
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private AuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAuthorizationResponse;
	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;
	private OAuth2ConsentHandler consentHandler = new DefaultOAuth2ConsentPageHandler();

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param authorizationEndpointUri the endpoint {@code URI} for authorization requests
	 */
	public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager, String authorizationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.authorizationEndpointMatcher = createDefaultRequestMatcher(authorizationEndpointUri);
		this.authenticationConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
	}

	private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
		RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.GET.name());
		RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.POST.name());
		RequestMatcher openidScopeMatcher = request -> {
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
		};
		RequestMatcher responseTypeParameterMatcher = request ->
				request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

		RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
				authorizationRequestGetMatcher,
				new AndRequestMatcher(
						authorizationRequestPostMatcher, responseTypeParameterMatcher, openidScopeMatcher));
		RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
				authorizationRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

		return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.authorizationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationConverter.convert(request);

			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
					(OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationManager.authenticate(authorizationCodeRequestAuthentication);

			if (!authorizationCodeRequestAuthenticationResult.isAuthenticated()) {
				// If the Principal (Resource Owner) is not authenticated then
				// pass through the chain with the expectation that the authentication process
				// will commence via AuthenticationEntryPoint
				filterChain.doFilter(request, response);
				return;
			}

			if (authorizationCodeRequestAuthenticationResult.isConsentRequired()) {
				consentHandler.handleConsent(request, response, authorizationCodeRequestAuthentication,
						authorizationCodeRequestAuthenticationResult);
				return;
			}

			this.authenticationSuccessHandler.onAuthenticationSuccess(
					request, response, authorizationCodeRequestAuthenticationResult);

		} catch (OAuth2AuthenticationException ex) {
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} used for authenticating the request.
	 *
	 * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * and returning the {@link OAuth2AuthorizationResponse Authorization Response}.
	 *
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * consentHandler is used to handle the consent process.
	 *
	 * @param consentHandler the consentHandler to set
	 */
	public void setConsentHandler(OAuth2ConsentHandler consentHandler) {
		this.consentHandler = consentHandler;
	}

	private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
				.queryParam(OAuth2ParameterNames.CODE, authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationCodeRequestAuthentication.getState());
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {

		OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException =
				(OAuth2AuthorizationCodeRequestAuthenticationException) exception;
		OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication();

		if (authorizationCodeRequestAuthentication == null ||
				!StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			// TODO Send default html error response
			response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
			return;
		}

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
				.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
		if (StringUtils.hasText(error.getDescription())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
		}
		if (StringUtils.hasText(error.getUri())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
		}
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationCodeRequestAuthentication.getState());
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

}
