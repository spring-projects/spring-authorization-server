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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.core.authentication.OAuth2AuthenticationValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Request (and Consent)
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {
	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
	private static final StringKeyGenerator DEFAULT_AUTHORIZATION_CODE_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
			new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private static final Function<String, OAuth2AuthenticationValidator> DEFAULT_AUTHENTICATION_VALIDATOR_RESOLVER =
			createDefaultAuthenticationValidatorResolver();
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final OAuth2AuthorizationConsentService authorizationConsentService;
	private Supplier<String> authorizationCodeGenerator = DEFAULT_AUTHORIZATION_CODE_GENERATOR::generateKey;
	private Function<String, OAuth2AuthenticationValidator> authenticationValidatorResolver = DEFAULT_AUTHENTICATION_VALIDATOR_RESOLVER;
	private Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authorizationConsentService, "authorizationConsentService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.authorizationConsentService = authorizationConsentService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		return authorizationCodeRequestAuthentication.isConsent() ?
				authenticateAuthorizationConsent(authentication) :
				authenticateAuthorizationRequest(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@code Supplier<String>} that generates the value for the {@link OAuth2AuthorizationCode}.
	 *
	 * @param authorizationCodeGenerator the {@code Supplier<String>} that generates the value for the {@link OAuth2AuthorizationCode}
	 */
	public void setAuthorizationCodeGenerator(Supplier<String> authorizationCodeGenerator) {
		Assert.notNull(authorizationCodeGenerator, "authorizationCodeGenerator cannot be null");
		this.authorizationCodeGenerator = authorizationCodeGenerator;
	}

	/**
	 * Sets the resolver that resolves an {@link OAuth2AuthenticationValidator} from the provided OAuth 2.0 Authorization Request parameter.
	 *
	 * <p>
	 * The following OAuth 2.0 Authorization Request parameters are supported:
	 * <ol>
	 * <li>{@link OAuth2ParameterNames#REDIRECT_URI}</li>
	 * <li>{@link OAuth2ParameterNames#SCOPE}</li>
	 * </ol>
	 *
	 * <p>
	 * <b>NOTE:</b> The resolved {@link OAuth2AuthenticationValidator} MUST throw {@link OAuth2AuthorizationCodeRequestAuthenticationException} if validation fails.
	 *
	 * @param authenticationValidatorResolver the resolver that resolves an {@link OAuth2AuthenticationValidator} from the provided OAuth 2.0 Authorization Request parameter
	 */
	public void setAuthenticationValidatorResolver(Function<String, OAuth2AuthenticationValidator> authenticationValidatorResolver) {
		Assert.notNull(authenticationValidatorResolver, "authenticationValidatorResolver cannot be null");
		this.authenticationValidatorResolver = authenticationValidatorResolver;
	}

	/**
	 * Sets the {@code Consumer} providing access to the {@link OAuth2AuthorizationConsentAuthenticationContext}
	 * containing an {@link OAuth2AuthorizationConsent.Builder} and additional context information.
	 *
	 * <p>
	 * The following context attributes are available:
	 * <ul>
	 * <li>The {@link OAuth2AuthorizationConsent.Builder} used to build the authorization consent
	 * prior to {@link OAuth2AuthorizationConsentService#save(OAuth2AuthorizationConsent)}.</li>
	 * <li>The {@link Authentication} of type
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.</li>
	 * <li>The {@link RegisteredClient} associated with the authorization request.</li>
	 * <li>The {@link OAuth2Authorization} associated with the state token presented in the
	 * authorization consent request.</li>
	 * <li>The {@link OAuth2AuthorizationRequest} associated with the authorization consent request.</li>
	 * </ul>
	 *
	 * @param authorizationConsentCustomizer the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationConsentAuthenticationContext} containing an {@link OAuth2AuthorizationConsent.Builder}
	 */
	public void setAuthorizationConsentCustomizer(Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer) {
		Assert.notNull(authorizationConsentCustomizer, "authorizationConsentCustomizer cannot be null");
		this.authorizationConsentCustomizer = authorizationConsentCustomizer;
	}

	private Authentication authenticateAuthorizationRequest(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationCodeRequestAuthentication.getClientId());
		if (registeredClient == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, null);
		}

		Map<Object, Object> context = new HashMap<>();
		context.put(RegisteredClient.class, registeredClient);
		OAuth2AuthenticationContext authenticationContext = new OAuth2AuthenticationContext(
				authorizationCodeRequestAuthentication, context);

		OAuth2AuthenticationValidator redirectUriValidator = resolveAuthenticationValidator(OAuth2ParameterNames.REDIRECT_URI);
		redirectUriValidator.validate(authenticationContext);

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient);
		}

		OAuth2AuthenticationValidator scopeValidator = resolveAuthenticationValidator(OAuth2ParameterNames.SCOPE);
		scopeValidator.validate(authenticationContext);

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge)) {
			String codeChallengeMethod = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
			if (StringUtils.hasText(codeChallengeMethod)) {
				if (!"S256".equals(codeChallengeMethod) && !"plain".equals(codeChallengeMethod)) {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI,
							authorizationCodeRequestAuthentication, registeredClient, null);
				}
			}
		} else if (registeredClient.getClientSettings().isRequireProofKey()) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI,
					authorizationCodeRequestAuthentication, registeredClient, null);
		}

		// ---------------
		// The request is valid - ensure the resource owner is authenticated
		// ---------------

		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal)) {
			// Return the authorization request as-is where isAuthenticated() is false
			return authorizationCodeRequestAuthentication;
		}

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
				.clientId(registeredClient.getClientId())
				.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
				.scopes(authorizationCodeRequestAuthentication.getScopes())
				.state(authorizationCodeRequestAuthentication.getState())
				.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
				.build();

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				registeredClient.getId(), principal.getName());

		if (requireAuthorizationConsent(registeredClient, authorizationRequest, currentAuthorizationConsent)) {
			String state = DEFAULT_STATE_GENERATOR.generateKey();
			OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
					.attribute(OAuth2ParameterNames.STATE, state)
					.build();
			this.authorizationService.save(authorization);

			// TODO Need to remove 'in-flight' authorization if consent step is not completed (e.g. approved or cancelled)

			Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
					currentAuthorizationConsent.getScopes() : null;

			return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
					.authorizationUri(authorizationRequest.getAuthorizationUri())
					.scopes(currentAuthorizedScopes)
					.state(state)
					.consentRequired(true)
					.build();
		}

		OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode();
		OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
				.token(authorizationCode)
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizationRequest.getScopes())
				.build();
		this.authorizationService.save(authorization);

		String redirectUri = authorizationRequest.getRedirectUri();
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}

		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.redirectUri(redirectUri)
				.scopes(authorizationRequest.getScopes())
				.state(authorizationRequest.getState())
				.authorizationCode(authorizationCode)
				.build();
	}

	private OAuth2AuthenticationValidator resolveAuthenticationValidator(String parameterName) {
		OAuth2AuthenticationValidator authenticationValidator = this.authenticationValidatorResolver.apply(parameterName);
		return authenticationValidator != null ?
				authenticationValidator :
				DEFAULT_AUTHENTICATION_VALIDATOR_RESOLVER.apply(parameterName);
	}

	private OAuth2AuthorizationCode generateAuthorizationCode() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);		// TODO Allow configuration for authorization code time-to-live
		return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.get(), issuedAt, expiresAt);
	}

	private Authentication authenticateAuthorizationConsent(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				(OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				authorizationCodeRequestAuthentication.getState(), STATE_TOKEN_TYPE);
		if (authorization == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
					authorizationCodeRequestAuthentication, null, null);
		}

		// The 'in-flight' authorization must be associated to the current principal
		Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal) || !principal.getName().equals(authorization.getPrincipalName())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
					authorizationCodeRequestAuthentication, null, null);
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationCodeRequestAuthentication.getClientId());
		if (registeredClient == null || !registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient);
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Set<String> requestedScopes = authorizationRequest.getScopes();
		Set<String> authorizedScopes = new HashSet<>(authorizationCodeRequestAuthentication.getScopes());
		if (!requestedScopes.containsAll(authorizedScopes)) {
			throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
					authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
		}

		OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
				authorization.getRegisteredClientId(), authorization.getPrincipalName());
		Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
				currentAuthorizationConsent.getScopes() : Collections.emptySet();

		if (!currentAuthorizedScopes.isEmpty()) {
			for (String requestedScope : requestedScopes) {
				if (currentAuthorizedScopes.contains(requestedScope)) {
					authorizedScopes.add(requestedScope);
				}
			}
		}

		if (!authorizedScopes.isEmpty() && requestedScopes.contains(OidcScopes.OPENID)) {
			// 'openid' scope is auto-approved as it does not require consent
			authorizedScopes.add(OidcScopes.OPENID);
		}

		OAuth2AuthorizationConsent.Builder authorizationConsentBuilder;
		if (currentAuthorizationConsent != null) {
			authorizationConsentBuilder = OAuth2AuthorizationConsent.from(currentAuthorizationConsent);
		} else {
			authorizationConsentBuilder = OAuth2AuthorizationConsent.withId(
					authorization.getRegisteredClientId(), authorization.getPrincipalName());
		}
		authorizedScopes.forEach(authorizationConsentBuilder::scope);

		if (this.authorizationConsentCustomizer != null) {
			// @formatter:off
			OAuth2AuthorizationConsentAuthenticationContext authorizationConsentAuthenticationContext =
					OAuth2AuthorizationConsentAuthenticationContext.with(authorizationCodeRequestAuthentication)
							.authorizationConsent(authorizationConsentBuilder)
							.registeredClient(registeredClient)
							.authorization(authorization)
							.authorizationRequest(authorizationRequest)
							.build();
			// @formatter:on
			this.authorizationConsentCustomizer.accept(authorizationConsentAuthenticationContext);
		}

		Set<GrantedAuthority> authorities = new HashSet<>();
		authorizationConsentBuilder.authorities(authorities::addAll);

		if (authorities.isEmpty()) {
			// Authorization consent denied (or revoked)
			if (currentAuthorizationConsent != null) {
				this.authorizationConsentService.remove(currentAuthorizationConsent);
			}
			this.authorizationService.remove(authorization);
			throwError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
		}

		OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
		if (!authorizationConsent.equals(currentAuthorizationConsent)) {
			this.authorizationConsentService.save(authorizationConsent);
		}

		OAuth2AuthorizationCode authorizationCode = generateAuthorizationCode();

		OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
				.token(authorizationCode)
				.attributes(attrs -> {
					attrs.remove(OAuth2ParameterNames.STATE);
					attrs.put(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes);
				})
				.build();
		this.authorizationService.save(updatedAuthorization);

		String redirectUri = authorizationRequest.getRedirectUri();
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}

		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.redirectUri(redirectUri)
				.scopes(authorizedScopes)
				.state(authorizationRequest.getState())
				.authorizationCode(authorizationCode)
				.build();
	}

	private static Function<String, OAuth2AuthenticationValidator> createDefaultAuthenticationValidatorResolver() {
		Map<String, OAuth2AuthenticationValidator> authenticationValidators = new HashMap<>();
		authenticationValidators.put(OAuth2ParameterNames.REDIRECT_URI, new DefaultRedirectUriOAuth2AuthenticationValidator());
		authenticationValidators.put(OAuth2ParameterNames.SCOPE, new DefaultScopeOAuth2AuthenticationValidator());
		return authenticationValidators::get;
	}

	private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient, Authentication principal,
			OAuth2AuthorizationRequest authorizationRequest) {
		return OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(principal.getName())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(Principal.class.getName(), principal)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
	}

	private static boolean requireAuthorizationConsent(RegisteredClient registeredClient,
			OAuth2AuthorizationRequest authorizationRequest, OAuth2AuthorizationConsent authorizationConsent) {

		if (!registeredClient.getClientSettings().isRequireAuthorizationConsent()) {
			return false;
		}
		// 'openid' scope does not require consent
		if (authorizationRequest.getScopes().contains(OidcScopes.OPENID) &&
				authorizationRequest.getScopes().size() == 1) {
			return false;
		}

		if (authorizationConsent != null &&
				authorizationConsent.getScopes().containsAll(authorizationRequest.getScopes())) {
			return false;
		}

		return true;
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
		if (!isLoopbackAddress(requestedRedirectHost)) {
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

	private static boolean isLoopbackAddress(String host) {
		// IPv6 loopback address should either be "0:0:0:0:0:0:0:1" or "::1"
		if ("[0:0:0:0:0:0:0:1]".equals(host) || "[::1]".equals(host)) {
			return true;
		}
		// IPv4 loopback address ranges from 127.0.0.1 to 127.255.255.255
		String[] ipv4Octets = host.split("\\.");
		if (ipv4Octets.length != 4) {
			return false;
		}
		try {
			int[] address = new int[ipv4Octets.length];
			for (int i=0; i < ipv4Octets.length; i++) {
				address[i] = Integer.parseInt(ipv4Octets[i]);
			}
			return address[0] == 127 && address[1] >= 0 && address[1] <= 255 && address[2] >= 0 &&
					address[2] <= 255 && address[3] >= 1 && address[3] <= 255;
		} catch (NumberFormatException ex) {
			return false;
		}
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null &&
				!AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
				principal.isAuthenticated();
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		throwError(errorCode, parameterName, authorizationCodeRequestAuthentication, registeredClient, null);
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		throwError(errorCode, parameterName, "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
				authorizationCodeRequestAuthentication, registeredClient, authorizationRequest);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {

		boolean redirectOnError = true;
		if (errorCode.equals(OAuth2ErrorCodes.INVALID_REQUEST) &&
				(parameterName.equals(OAuth2ParameterNames.CLIENT_ID) ||
						parameterName.equals(OAuth2ParameterNames.REDIRECT_URI) ||
						parameterName.equals(OAuth2ParameterNames.STATE))) {
			redirectOnError = false;
		}

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = authorizationCodeRequestAuthentication;

		if (redirectOnError && !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			String redirectUri = resolveRedirectUri(authorizationRequest, registeredClient);
			String state = authorizationCodeRequestAuthentication.isConsent() && authorizationRequest != null ?
					authorizationRequest.getState() : authorizationCodeRequestAuthentication.getState();
			authorizationCodeRequestAuthenticationResult = from(authorizationCodeRequestAuthentication)
					.redirectUri(redirectUri)
					.state(state)
					.build();
			authorizationCodeRequestAuthenticationResult.setAuthenticated(authorizationCodeRequestAuthentication.isAuthenticated());
		} else if (!redirectOnError && StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
			authorizationCodeRequestAuthenticationResult = from(authorizationCodeRequestAuthentication)
					.redirectUri(null)		// Prevent redirects
					.build();
			authorizationCodeRequestAuthenticationResult.setAuthenticated(authorizationCodeRequestAuthentication.isAuthenticated());
		}

		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
	}

	private static String resolveRedirectUri(OAuth2AuthorizationRequest authorizationRequest, RegisteredClient registeredClient) {
		if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
			return authorizationRequest.getRedirectUri();
		}
		if (registeredClient != null) {
			return registeredClient.getRedirectUris().iterator().next();
		}
		return null;
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationToken.Builder from(OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
		return OAuth2AuthorizationCodeRequestAuthenticationToken.with(authorizationCodeRequestAuthentication.getClientId(), (Authentication) authorizationCodeRequestAuthentication.getPrincipal())
				.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
				.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
				.scopes(authorizationCodeRequestAuthentication.getScopes())
				.state(authorizationCodeRequestAuthentication.getState())
				.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
				.authorizationCode(authorizationCodeRequestAuthentication.getAuthorizationCode());
	}

	private static class DefaultRedirectUriOAuth2AuthenticationValidator implements OAuth2AuthenticationValidator {

		@Override
		public void validate(OAuth2AuthenticationContext authenticationContext) {
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					authenticationContext.getAuthentication();
			RegisteredClient registeredClient = authenticationContext.get(RegisteredClient.class);

			if (StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
				if (!isValidRedirectUri(authorizationCodeRequestAuthentication.getRedirectUri(), registeredClient)) {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
							authorizationCodeRequestAuthentication, registeredClient);
				}
			} else if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID) ||
					registeredClient.getRedirectUris().size() != 1) {
				// redirect_uri is REQUIRED for OpenID Connect
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
						authorizationCodeRequestAuthentication, registeredClient);
			}
		}

	}

	private static class DefaultScopeOAuth2AuthenticationValidator implements OAuth2AuthenticationValidator {

		@Override
		public void validate(OAuth2AuthenticationContext authenticationContext) {
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
					authenticationContext.getAuthentication();
			RegisteredClient registeredClient = authenticationContext.get(RegisteredClient.class);

			Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
			Set<String> allowedScopes = registeredClient.getScopes();
			if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
				throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
						authorizationCodeRequestAuthentication, registeredClient);
			}
		}

	}

}
