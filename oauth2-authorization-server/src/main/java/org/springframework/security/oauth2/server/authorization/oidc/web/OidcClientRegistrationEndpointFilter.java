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
package org.springframework.security.oauth2.server.authorization.oidc.web;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * A {@code Filter} that processes OpenID Client Registration Requests.
 * @author Ovidiu Popa
 * @since 0.1.1
 * @see OidcClientRegistration
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration">3.1.  Client Registration Request</a>
 */
public class OidcClientRegistrationEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for OpenID Client Registration requests.
	 */
	public static final String DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI = "/connect/register";
	private static final String SCOPE_CLAIM_DELIMITER = " ";

	private final OidcClientRegistrationHttpMessageConverter clientRegistrationHttpMessageConverter =
			new OidcClientRegistrationHttpMessageConverter();
	private final RegisteredClientRepository registeredClientRepository;
	private final OidcClientRegistrationToRegisteredClientConverter oidcClientToRegisteredClientConverter =
			new OidcClientRegistrationToRegisteredClientConverter();
	private final RegisteredClientToOidcClientRegistrationConverter registeredClientToOidcClientConverter =
			new RegisteredClientToOidcClientRegistrationConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();
	private final RequestMatcher requestMatcher;
	private final AuthenticationManager authenticationManager;

	/**
	 * Constructs an {@code OidcClientRegistrationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authenticationManager the authentication manager
	 */
	public OidcClientRegistrationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			AuthenticationManager authenticationManager) {
		this(registeredClientRepository, authenticationManager, DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OidcClientRegistrationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authenticationManager the authentication manager
	 * @param oidcClientRegistrationUri the endpoint {@code URI} for OIDC Client Registration requests
	 */
	public OidcClientRegistrationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			AuthenticationManager authenticationManager, String oidcClientRegistrationUri) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(oidcClientRegistrationUri, "oidcClientRegistrationUri cannot be empty");
		this.registeredClientRepository = registeredClientRepository;
		this.authenticationManager = authenticationManager;
		this.requestMatcher = new AntPathRequestMatcher(
				oidcClientRegistrationUri,
				HttpMethod.POST.name()
		);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			authenticationManager.authenticate(authentication);
			OidcClientRegistration clientRegistrationRequest =
					this.clientRegistrationHttpMessageConverter.read(OidcClientRegistration.class, new ServletServerHttpRequest(request));

			RegisteredClient registeredClient = this.oidcClientToRegisteredClientConverter
					.convert(clientRegistrationRequest);
			this.registeredClientRepository.saveClient(registeredClient);

			OidcClientRegistration convert = this.registeredClientToOidcClientConverter
					.convert(registeredClient);

			final ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
			httpResponse.setStatusCode(HttpStatus.CREATED);
			this.clientRegistrationHttpMessageConverter.write(
					convert, MediaType.APPLICATION_JSON, httpResponse);
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			sendErrorResponse(response, ex.getError());
		}
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	private static class OidcClientRegistrationToRegisteredClientConverter implements Converter<OidcClientRegistration, RegisteredClient> {

		@Override
		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			return RegisteredClient.withId(UUID.randomUUID().toString())
					.clientId(UUID.randomUUID().toString())
					.clientSecret(UUID.randomUUID().toString())
					.redirectUris(redirectUris ->
							redirectUris.addAll(clientRegistration.getRedirectUris()))
					.clientAuthenticationMethod(new ClientAuthenticationMethod(clientRegistration.getTokenEndpointAuthenticationMethod()))
					.authorizationGrantTypes(grantTypes ->
							grantTypes.addAll(this.grantTypes(clientRegistration)))
					.scopes(scopes ->
							scopes.addAll(Arrays.asList(clientRegistration.getScope().split(SCOPE_CLAIM_DELIMITER))))
					.clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
					.build();
		}

		private List<AuthorizationGrantType> grantTypes(OidcClientRegistration clientRegistration) {
			return clientRegistration.getGrantTypes().stream()
					.map(AuthorizationGrantType::new)
					.collect(Collectors.toList());
		}
	}

	private static class RegisteredClientToOidcClientRegistrationConverter implements Converter<RegisteredClient, OidcClientRegistration> {

		@Override
		public OidcClientRegistration convert(RegisteredClient source) {
			return OidcClientRegistration.builder()
					.clientId(source.getClientId())
					.redirectUris(uris -> uris.addAll(source.getRedirectUris()))
					.clientIdIssuedAt(Instant.now())
					.clientSecret(source.getClientSecret())
					.clientSecretExpiresAt(Instant.EPOCH)
					.responseType(OAuth2AuthorizationResponseType.CODE.getValue())
					.grantTypes(grantTypes ->
							grantTypes.addAll(source.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue)
									.collect(Collectors.toList()))
					)
					.scope(String.join(SCOPE_CLAIM_DELIMITER, source.getScopes()))
					.tokenEndpointAuthenticationMethod(source.getClientAuthenticationMethods().iterator().next().getValue())
					.build();
		}
	}
}
