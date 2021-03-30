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
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Authorization Request.
 *
 * @author Joe Grandja
 * @author Paurav Munshi
 * @author Daniel Garnier-Moiroux
 * @author Anoop Garlapati
 * @since 0.0.1
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2Authorization
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for authorization requests.
	 */
	public static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
	private static final String PKCE_ERROR_URI = "https://tools.ietf.org/html/rfc7636#section-4.4.1";
	private static final Pattern LOOPBACK_ADDRESS_PATTERN =
			Pattern.compile("^127(?:\\.[0-9]+){0,2}\\.[0-9]+$|^\\[(?:0*:)*?:?0*1]$");

	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final RequestMatcher authorizationRequestMatcher;
	private final RequestMatcher userConsentMatcher;
	private final StringKeyGenerator codeGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	private UserConsentPage userConsentPage = new UserConsentPage(){};

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		this(registeredClientRepository, authorizationService, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationEndpointUri the endpoint {@code URI} for authorization requests
	 */
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, String authorizationEndpointUri) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.hasText(authorizationEndpointUri, "authorizationEndpointUri cannot be empty");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;

		RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.GET.name());
		RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.POST.name());
		RequestMatcher openidScopeMatcher = request -> {
			String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
			return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
		};
		RequestMatcher consentActionMatcher = request ->
				request.getParameter(UserConsentPage.CONSENT_ACTION_PARAMETER_NAME) != null;
		this.authorizationRequestMatcher = new OrRequestMatcher(
				authorizationRequestGetMatcher,
				new AndRequestMatcher(
						authorizationRequestPostMatcher, openidScopeMatcher,
						new NegatedRequestMatcher(consentActionMatcher)));
		this.userConsentMatcher = new AndRequestMatcher(
				authorizationRequestPostMatcher, consentActionMatcher);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.authorizationRequestMatcher.matches(request)) {
			processAuthorizationRequest(request, response, filterChain);
		} else if (this.userConsentMatcher.matches(request)) {
			processUserConsent(request, response);
		} else {
			filterChain.doFilter(request, response);
		}
	}

	private void processAuthorizationRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		OAuth2AuthorizationRequestContext authorizationRequestContext =
				new OAuth2AuthorizationRequestContext(
						request.getRequestURL().toString(),
						OAuth2EndpointUtils.getParameters(request));

		validateAuthorizationRequest(authorizationRequestContext);

		if (authorizationRequestContext.hasError()) {
			if (authorizationRequestContext.isRedirectOnError()) {
				sendErrorResponse(request, response, authorizationRequestContext.resolveRedirectUri(),
						authorizationRequestContext.getError(), authorizationRequestContext.getState());
			} else {
				sendErrorResponse(response, authorizationRequestContext.getError());
			}
			return;
		}

		// ---------------
		// The request is valid - ensure the resource owner is authenticated
		// ---------------

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (!isPrincipalAuthenticated(principal)) {
			// Pass through the chain with the expectation that the authentication process
			// will commence via AuthenticationEntryPoint
			filterChain.doFilter(request, response);
			return;
		}

		RegisteredClient registeredClient = authorizationRequestContext.getRegisteredClient();
		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestContext.buildAuthorizationRequest();
		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(principal.getName())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(Principal.class.getName(), principal)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);

		if (requireUserConsent(registeredClient, authorizationRequest)) {
			String state = this.stateGenerator.generateKey();
			OAuth2Authorization authorization = builder
					.attribute(OAuth2ParameterNames.STATE, state)
					.build();
			this.authorizationService.save(authorization);

			// TODO Need to remove 'in-flight' authorization if consent step is not completed (e.g. approved or cancelled)

			this.userConsentPage.displayConsent(request, response, registeredClient, authorization);
		} else {
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);		// TODO Allow configuration for authorization code time-to-live
			OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
					this.codeGenerator.generateKey(), issuedAt, expiresAt);
			OAuth2Authorization authorization = builder
					.token(authorizationCode)
					.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizationRequest.getScopes())
					.build();
			this.authorizationService.save(authorization);

//			TODO security checks for code parameter
//			The authorization code MUST expire shortly after it is issued to mitigate the risk of leaks.
//			A maximum authorization code lifetime of 10 minutes is RECOMMENDED.
//			The client MUST NOT use the authorization code more than once.
//			If an authorization code is used more than once, the authorization server MUST deny the request
//			and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.
//			The authorization code is bound to the client identifier and redirection URI.

			sendAuthorizationResponse(request, response,
					authorizationRequestContext.resolveRedirectUri(), authorizationCode, authorizationRequest.getState());
		}
	}

	private static boolean requireUserConsent(RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		// openid scope does not require consent
		if (authorizationRequest.getScopes().contains(OidcScopes.OPENID) &&
				authorizationRequest.getScopes().size() == 1) {
			return false;
		}
		return registeredClient.getClientSettings().requireUserConsent();
	}

	private void processUserConsent(HttpServletRequest request, HttpServletResponse response)
			throws IOException {

		UserConsentRequestContext userConsentRequestContext =
				new UserConsentRequestContext(
						request.getRequestURL().toString(),
						OAuth2EndpointUtils.getParameters(request));

		validateUserConsentRequest(userConsentRequestContext);

		if (userConsentRequestContext.hasError()) {
			if (userConsentRequestContext.isRedirectOnError()) {
				sendErrorResponse(request, response, userConsentRequestContext.resolveRedirectUri(),
						userConsentRequestContext.getError(), userConsentRequestContext.getState());
			} else {
				sendErrorResponse(response, userConsentRequestContext.getError());
			}
			return;
		}

		if (!this.userConsentPage.isConsentApproved(request)) {
			this.authorizationService.remove(userConsentRequestContext.getAuthorization());
			OAuth2Error error = createError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID);
			sendErrorResponse(request, response, userConsentRequestContext.resolveRedirectUri(),
					error, userConsentRequestContext.getAuthorizationRequest().getState());
			return;
		}

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);		// TODO Allow configuration for authorization code time-to-live
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
				this.codeGenerator.generateKey(), issuedAt, expiresAt);
		Set<String> authorizedScopes = userConsentRequestContext.getScopes();
		if (userConsentRequestContext.getAuthorizationRequest().getScopes().contains(OidcScopes.OPENID)) {
			// openid scope is auto-approved as it does not require consent
			authorizedScopes.add(OidcScopes.OPENID);
		}
		OAuth2Authorization authorization = OAuth2Authorization.from(userConsentRequestContext.getAuthorization())
				.token(authorizationCode)
				.attributes(attrs -> {
					attrs.remove(OAuth2ParameterNames.STATE);
					attrs.put(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes);
				})
				.build();
		this.authorizationService.save(authorization);

		sendAuthorizationResponse(request, response, userConsentRequestContext.resolveRedirectUri(),
				authorizationCode, userConsentRequestContext.getAuthorizationRequest().getState());
	}

	private void validateAuthorizationRequest(OAuth2AuthorizationRequestContext authorizationRequestContext) {
		// ---------------
		// Validate the request to ensure all required parameters are present and valid
		// ---------------

		// client_id (REQUIRED)
		if (!StringUtils.hasText(authorizationRequestContext.getClientId()) ||
				authorizationRequestContext.getParameters().get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID));
			return;
		}
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationRequestContext.getClientId());
		if (registeredClient == null) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID));
			return;
		} else if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID));
			return;
		}
		authorizationRequestContext.setRegisteredClient(registeredClient);

		// redirect_uri (OPTIONAL)
		if (StringUtils.hasText(authorizationRequestContext.getRedirectUri())) {
			if (!isValidRedirectUri(authorizationRequestContext.getRedirectUri(), registeredClient) ||
					authorizationRequestContext.getParameters().get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
				authorizationRequestContext.setError(
						createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI));
				return;
			}
		} else if (authorizationRequestContext.isAuthenticationRequest() ||		// redirect_uri is REQUIRED for OpenID Connect
				registeredClient.getRedirectUris().size() != 1) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI));
			return;
		}
		authorizationRequestContext.setRedirectOnError(true);

		// response_type (REQUIRED)
		if (!StringUtils.hasText(authorizationRequestContext.getResponseType()) ||
				authorizationRequestContext.getParameters().get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE));
			return;
		} else if (!authorizationRequestContext.getResponseType().equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE));
			return;
		}

		// scope (OPTIONAL)
		Set<String> requestedScopes = authorizationRequestContext.getScopes();
		Set<String> allowedScopes = registeredClient.getScopes();
		if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE));
			return;
		}

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = authorizationRequestContext.getParameters().getFirst(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge)) {
			if (authorizationRequestContext.getParameters().get(PkceParameterNames.CODE_CHALLENGE).size() != 1) {
				authorizationRequestContext.setError(
						createError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI));
				return;
			}

			String codeChallengeMethod = authorizationRequestContext.getParameters().getFirst(PkceParameterNames.CODE_CHALLENGE_METHOD);
			if (StringUtils.hasText(codeChallengeMethod)) {
				if (authorizationRequestContext.getParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD).size() != 1 ||
						(!"S256".equals(codeChallengeMethod) && !"plain".equals(codeChallengeMethod))) {
					authorizationRequestContext.setError(
							createError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI));
					return;
				}
			}
		} else if (registeredClient.getClientSettings().requireProofKey()) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI));
			return;
		}
	}

	private void validateUserConsentRequest(UserConsentRequestContext userConsentRequestContext) {
		// ---------------
		// Validate the request to ensure all required parameters are present and valid
		// ---------------

		// state (REQUIRED)
		if (!StringUtils.hasText(userConsentRequestContext.getState()) ||
				userConsentRequestContext.getParameters().get(OAuth2ParameterNames.STATE).size() != 1) {
			userConsentRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE));
			return;
		}
		OAuth2Authorization authorization = this.authorizationService.findByToken(
				userConsentRequestContext.getState(), STATE_TOKEN_TYPE);
		if (authorization == null) {
			userConsentRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE));
			return;
		}
		userConsentRequestContext.setAuthorization(authorization);

		// The 'in-flight' authorization must be associated to the current principal
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (!isPrincipalAuthenticated(principal) || !principal.getName().equals(authorization.getPrincipalName())) {
			userConsentRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE));
			return;
		}

		// client_id (REQUIRED)
		if (!StringUtils.hasText(userConsentRequestContext.getClientId()) ||
				userConsentRequestContext.getParameters().get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			userConsentRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID));
			return;
		}
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				userConsentRequestContext.getClientId());
		if (registeredClient == null || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			userConsentRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID));
			return;
		}
		userConsentRequestContext.setRegisteredClient(registeredClient);
		userConsentRequestContext.setRedirectOnError(true);

		// scope (OPTIONAL)
		Set<String> requestedScopes = userConsentRequestContext.getAuthorizationRequest().getScopes();
		Set<String> authorizedScopes = userConsentRequestContext.getScopes();
		if (!authorizedScopes.isEmpty() && !requestedScopes.containsAll(authorizedScopes)) {
			userConsentRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE));
			return;
		}
	}

	private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			String redirectUri, OAuth2AuthorizationCode authorizationCode, String state) throws IOException {

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.CODE, authorizationCode.getTokenValue());
		if (StringUtils.hasText(state)) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			String redirectUri, OAuth2Error error, String state) throws IOException {

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
		if (StringUtils.hasText(error.getDescription())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
		}
		if (StringUtils.hasText(error.getUri())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
		}
		if (StringUtils.hasText(state)) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		// TODO Send default html error response
		response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
	}

	private static OAuth2Error createError(String errorCode, String parameterName) {
		return createError(errorCode, parameterName, "https://tools.ietf.org/html/rfc6749#section-4.1.2.1");
	}

	private static OAuth2Error createError(String errorCode, String parameterName, String errorUri) {
		return new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null &&
				!AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
				principal.isAuthenticated();
	}

	private static boolean isValidRedirectUri(String requestedRedirectUri, RegisteredClient registeredClient) {
		UriComponents requestedRedirect;
		try {
			requestedRedirect = UriComponentsBuilder.fromUriString(requestedRedirectUri).build();
			if (requestedRedirect.getFragment() != null) {
				return false;
			}
		} catch (Exception ex) {
			return false;
		}

		String requestedRedirectHost = requestedRedirect.getHost();
		if (requestedRedirectHost == null || requestedRedirectHost.equals("localhost")) {
			// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-9.7.1
			// While redirect URIs using localhost (i.e.,
			// "http://localhost:{port}/{path}") function similarly to loopback IP
			// redirects described in Section 10.3.3, the use of "localhost" is NOT RECOMMENDED.
			return false;
		}
		if (!LOOPBACK_ADDRESS_PATTERN.matcher(requestedRedirectHost).matches()) {
			// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-9.7
			// When comparing client redirect URIs against pre-registered URIs,
			// authorization servers MUST utilize exact string matching.
			return registeredClient.getRedirectUris().contains(requestedRedirectUri);
		}

		// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-10.3.3
		// The authorization server MUST allow any port to be specified at the
		// time of the request for loopback IP redirect URIs, to accommodate
		// clients that obtain an available ephemeral port from the operating
		// system at the time of the request.
		for (String registeredRedirectUri : registeredClient.getRedirectUris()) {
			UriComponentsBuilder registeredRedirect = UriComponentsBuilder.fromUriString(registeredRedirectUri);
			registeredRedirect.port(requestedRedirect.getPort());
			if (registeredRedirect.build().toString().equals(requestedRedirect.toString())) {
				return true;
			}
		}
		return false;
	}

	public void setUserConsentPage(UserConsentPage userConsentPage){
		this.userConsentPage = userConsentPage;
	}

	public UserConsentPage getUserConsentPage(){
		return this.userConsentPage;
	}

	private static class OAuth2AuthorizationRequestContext extends AbstractRequestContext {
		private final String responseType;
		private final String redirectUri;

		private OAuth2AuthorizationRequestContext(
				String authorizationUri, MultiValueMap<String, String> parameters) {
			super(authorizationUri, parameters,
					parameters.getFirst(OAuth2ParameterNames.CLIENT_ID),
					parameters.getFirst(OAuth2ParameterNames.STATE),
					extractScopes(parameters));
			this.responseType = parameters.getFirst(OAuth2ParameterNames.RESPONSE_TYPE);
			this.redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		}

		private static Set<String> extractScopes(MultiValueMap<String, String> parameters) {
			String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
			return StringUtils.hasText(scope) ?
					new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " "))) :
					Collections.emptySet();
		}

		private String getResponseType() {
			return this.responseType;
		}

		private String getRedirectUri() {
			return this.redirectUri;
		}

		private boolean isAuthenticationRequest() {
			return getScopes().contains(OidcScopes.OPENID);
		}

		protected String resolveRedirectUri() {
			return StringUtils.hasText(getRedirectUri()) ?
					getRedirectUri() :
					getRegisteredClient().getRedirectUris().iterator().next();
		}

		private OAuth2AuthorizationRequest buildAuthorizationRequest() {
			return OAuth2AuthorizationRequest.authorizationCode()
					.authorizationUri(getAuthorizationUri())
					.clientId(getClientId())
					.redirectUri(getRedirectUri())
					.scopes(getScopes())
					.state(getState())
					.additionalParameters(additionalParameters ->
							getParameters().entrySet().stream()
									.filter(e -> !e.getKey().equals(OAuth2ParameterNames.RESPONSE_TYPE) &&
											!e.getKey().equals(OAuth2ParameterNames.CLIENT_ID) &&
											!e.getKey().equals(OAuth2ParameterNames.REDIRECT_URI) &&
											!e.getKey().equals(OAuth2ParameterNames.SCOPE) &&
											!e.getKey().equals(OAuth2ParameterNames.STATE))
									.forEach(e -> additionalParameters.put(e.getKey(), e.getValue().get(0))))
					.build();
		}
	}

	private static class UserConsentRequestContext extends AbstractRequestContext {
		private OAuth2Authorization authorization;

		private UserConsentRequestContext(
				String authorizationUri, MultiValueMap<String, String> parameters) {
			super(authorizationUri, parameters,
					parameters.getFirst(OAuth2ParameterNames.CLIENT_ID),
					parameters.getFirst(OAuth2ParameterNames.STATE),
					extractScopes(parameters));
		}

		private static Set<String> extractScopes(MultiValueMap<String, String> parameters) {
			List<String> scope = parameters.get(OAuth2ParameterNames.SCOPE);
			return !CollectionUtils.isEmpty(scope) ? new HashSet<>(scope) : Collections.emptySet();
		}

		private OAuth2Authorization getAuthorization() {
			return this.authorization;
		}

		private void setAuthorization(OAuth2Authorization authorization) {
			this.authorization = authorization;
		}

		protected String resolveRedirectUri() {
			OAuth2AuthorizationRequest authorizationRequest = getAuthorizationRequest();
			return StringUtils.hasText(authorizationRequest.getRedirectUri()) ?
					authorizationRequest.getRedirectUri() :
					getRegisteredClient().getRedirectUris().iterator().next();
		}

		private OAuth2AuthorizationRequest getAuthorizationRequest() {
			return getAuthorization().getAttribute(OAuth2AuthorizationRequest.class.getName());
		}
	}

	private abstract static class AbstractRequestContext {
		private final String authorizationUri;
		private final MultiValueMap<String, String> parameters;
		private final String clientId;
		private final String state;
		private final Set<String> scopes;
		private RegisteredClient registeredClient;
		private OAuth2Error error;
		private boolean redirectOnError;

		protected AbstractRequestContext(String authorizationUri, MultiValueMap<String, String> parameters,
				String clientId, String state, Set<String> scopes) {
			this.authorizationUri = authorizationUri;
			this.parameters = parameters;
			this.clientId = clientId;
			this.state = state;
			this.scopes = scopes;
		}

		protected String getAuthorizationUri() {
			return this.authorizationUri;
		}

		protected MultiValueMap<String, String> getParameters() {
			return this.parameters;
		}

		protected String getClientId() {
			return this.clientId;
		}

		protected String getState() {
			return this.state;
		}

		protected Set<String> getScopes() {
			return this.scopes;
		}

		protected RegisteredClient getRegisteredClient() {
			return this.registeredClient;
		}

		protected void setRegisteredClient(RegisteredClient registeredClient) {
			this.registeredClient = registeredClient;
		}

		protected OAuth2Error getError() {
			return this.error;
		}

		protected void setError(OAuth2Error error) {
			this.error = error;
		}

		protected boolean hasError() {
			return getError() != null;
		}

		protected boolean isRedirectOnError() {
			return this.redirectOnError;
		}

		protected void setRedirectOnError(boolean redirectOnError) {
			this.redirectOnError = redirectOnError;
		}

		protected abstract String resolveRedirectUri();
	}

}
