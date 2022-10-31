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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationConsentAuthenticationConverter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;
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
 * which handles the processing of the OAuth 2.0 Authorization Request and Consent.
 *
 * @author Joe Grandja
 * @author Paurav Munshi
 * @author Daniel Garnier-Moiroux
 * @author Anoop Garlapati
 * @author Dmitriy Dubson
 * @since 0.0.1
 * @see AuthenticationManager
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationConsentAuthenticationProvider
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
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private AuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAuthorizationResponse;
	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;
	private String consentPage;

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
		this.authenticationConverter = new DelegatingAuthenticationConverter(
				Arrays.asList(
						new OAuth2AuthorizationCodeRequestAuthenticationConverter(),
						new OAuth2AuthorizationConsentAuthenticationConverter()));
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
			Authentication authentication = this.authenticationConverter.convert(request);
			if (authentication instanceof AbstractAuthenticationToken) {
				((AbstractAuthenticationToken) authentication)
						.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}
			Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

			if (!authenticationResult.isAuthenticated()) {
				// If the Principal (Resource Owner) is not authenticated then
				// pass through the chain with the expectation that the authentication process
				// will commence via AuthenticationEntryPoint
				filterChain.doFilter(request, response);
				return;
			}

			if (authenticationResult instanceof OAuth2AuthorizationConsentAuthenticationToken) {
				sendAuthorizationConsent(request, response,
						(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication,
						(OAuth2AuthorizationConsentAuthenticationToken) authenticationResult);
				return;
			}

			this.authenticationSuccessHandler.onAuthenticationSuccess(
					request, response, authenticationResult);

		} catch (OAuth2AuthenticationException ex) {
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}.
	 *
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}
	 * @since 0.3.1
	 */
	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} or {@link OAuth2AuthorizationConsentAuthenticationToken}
	 * used for authenticating the request.
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
	 * Specify the URI to redirect Resource Owners to if consent is required. A default consent
	 * page will be generated when this attribute is not specified.
	 *
	 * @param consentPage the URI of the custom consent page to redirect to if consent is required (e.g. "/oauth2/consent")
	 */
	public void setConsentPage(String consentPage) {
		this.consentPage = consentPage;
	}

	private void sendAuthorizationConsent(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication) throws IOException {

		String clientId = authorizationConsentAuthentication.getClientId();
		Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
		Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
		Set<String> authorizedScopes = authorizationConsentAuthentication.getScopes();
		String state = authorizationConsentAuthentication.getState();

		if (hasConsentUri()) {
			String redirectUri = UriComponentsBuilder.fromUriString(resolveConsentUri(request))
					.queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", requestedScopes))
					.queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
					.queryParam(OAuth2ParameterNames.STATE, state)
					.toUriString();
			this.redirectStrategy.sendRedirect(request, response, redirectUri);
		} else {
			DefaultConsentPage.displayConsent(request, response, clientId, principal, requestedScopes, authorizedScopes, state);
		}
	}

	private boolean hasConsentUri() {
		return StringUtils.hasText(this.consentPage);
	}

	private String resolveConsentUri(HttpServletRequest request) {
		if (UrlUtils.isAbsoluteUrl(this.consentPage)) {
			return this.consentPage;
		}
		RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
		urlBuilder.setScheme(request.getScheme());
		urlBuilder.setServerName(request.getServerName());
		urlBuilder.setPort(request.getServerPort());
		urlBuilder.setContextPath(request.getContextPath());
		urlBuilder.setPathInfo(this.consentPage);
		return urlBuilder.getUrl();
	}

	private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
				.queryParam(OAuth2ParameterNames.CODE, authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
		String redirectUri;
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, "{state}");
			Map<String, String> queryParams = new HashMap<>();
			queryParams.put(OAuth2ParameterNames.STATE, authorizationCodeRequestAuthentication.getState());
			redirectUri = uriBuilder.build(queryParams).toString();
		} else {
			redirectUri = uriBuilder.toUriString();
		}
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
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
		String redirectUri;
		if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, "{state}");
			Map<String, String> queryParams = new HashMap<>();
			queryParams.put(OAuth2ParameterNames.STATE, authorizationCodeRequestAuthentication.getState());
			redirectUri = uriBuilder.build(queryParams).toString();
		} else {
			redirectUri = uriBuilder.toUriString();
		}
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

	/**
	 * For internal use only.
	 */
	private static class DefaultConsentPage {
		private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

		private static void displayConsent(HttpServletRequest request, HttpServletResponse response,
				String clientId, Authentication principal, Set<String> requestedScopes, Set<String> authorizedScopes, String state)
				throws IOException {

			String consentPage = generateConsentPage(request, clientId, principal, requestedScopes, authorizedScopes, state);
			response.setContentType(TEXT_HTML_UTF8.toString());
			response.setContentLength(consentPage.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(consentPage);
		}

		private static String generateConsentPage(HttpServletRequest request,
				String clientId, Authentication principal, Set<String> requestedScopes, Set<String> authorizedScopes, String state) {
			Set<String> scopesToAuthorize = new HashSet<>();
			Set<String> scopesPreviouslyAuthorized = new HashSet<>();
			for (String scope : requestedScopes) {
				if (authorizedScopes.contains(scope)) {
					scopesPreviouslyAuthorized.add(scope);
				} else if (!scope.equals(OidcScopes.OPENID)) { // openid scope does not require consent
					scopesToAuthorize.add(scope);
				}
			}

			StringBuilder builder = new StringBuilder();

			builder.append("<!DOCTYPE html>");
			builder.append("<html lang=\"en\">");
			builder.append("<head>");
			builder.append("    <meta charset=\"utf-8\">");
			builder.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">");
			builder.append("    <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css\" integrity=\"sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z\" crossorigin=\"anonymous\">");
			builder.append("    <title>Consent required</title>");
			builder.append("	<script>");
			builder.append("		function cancelConsent() {");
			builder.append("			document.consent_form.reset();");
			builder.append("			document.consent_form.submit();");
			builder.append("		}");
			builder.append("	</script>");
			builder.append("</head>");
			builder.append("<body>");
			builder.append("<div class=\"container\">");
			builder.append("    <div class=\"py-5\">");
			builder.append("        <h1 class=\"text-center\">Consent required</h1>");
			builder.append("    </div>");
			builder.append("    <div class=\"row\">");
			builder.append("        <div class=\"col text-center\">");
			builder.append("            <p><span class=\"font-weight-bold text-primary\">" + clientId + "</span> wants to access your account <span class=\"font-weight-bold\">" + principal.getName() + "</span></p>");
			builder.append("        </div>");
			builder.append("    </div>");
			builder.append("    <div class=\"row pb-3\">");
			builder.append("        <div class=\"col text-center\">");
			builder.append("            <p>The following permissions are requested by the above app.<br/>Please review these and consent if you approve.</p>");
			builder.append("        </div>");
			builder.append("    </div>");
			builder.append("    <div class=\"row\">");
			builder.append("        <div class=\"col text-center\">");
			builder.append("            <form name=\"consent_form\" method=\"post\" action=\"" + request.getRequestURI() + "\">");
			builder.append("                <input type=\"hidden\" name=\"client_id\" value=\"" + clientId + "\">");
			builder.append("                <input type=\"hidden\" name=\"state\" value=\"" + state + "\">");

			for (String scope : scopesToAuthorize) {
				builder.append("                <div class=\"form-group form-check py-1\">");
				builder.append("                    <input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"" + scope + "\" id=\"" + scope + "\">");
				builder.append("                    <label class=\"form-check-label\" for=\"" + scope + "\">" + scope + "</label>");
				builder.append("                </div>");
			}

			if (!scopesPreviouslyAuthorized.isEmpty()) {
				builder.append("                <p>You have already granted the following permissions to the above app:</p>");
				for (String scope : scopesPreviouslyAuthorized) {
					builder.append("                <div class=\"form-group form-check py-1\">");
					builder.append("                    <input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" id=\"" + scope + "\" checked disabled>");
					builder.append("                    <label class=\"form-check-label\" for=\"" + scope + "\">" + scope + "</label>");
					builder.append("                </div>");
				}
			}

			builder.append("                <div class=\"form-group pt-3\">");
			builder.append("                    <button class=\"btn btn-primary btn-lg\" type=\"submit\" id=\"submit-consent\">Submit Consent</button>");
			builder.append("                </div>");
			builder.append("                <div class=\"form-group\">");
			builder.append("                    <button class=\"btn btn-link regular\" type=\"button\" onclick=\"cancelConsent();\" id=\"cancel-consent\">Cancel</button>");
			builder.append("                </div>");
			builder.append("            </form>");
			builder.append("        </div>");
			builder.append("    </div>");
			builder.append("    <div class=\"row pt-4\">");
			builder.append("        <div class=\"col text-center\">");
			builder.append("            <p><small>Your consent to provide access is required.<br/>If you do not approve, click Cancel, in which case no information will be shared with the app.</small></p>");
			builder.append("        </div>");
			builder.append("    </div>");
			builder.append("</div>");
			builder.append("</body>");
			builder.append("</html>");

			return builder.toString();
		}
	}
}
