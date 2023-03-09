/*
 * Copyright 2020-2023 the original author or authors.
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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2DeviceAuthorizationResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceAuthorizationRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} for the OAuth 2.0 Device Authorization Grant,
 * which handles the processing of the OAuth 2.0 Device Authorization Request.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see AuthenticationManager
 * @see OAuth2DeviceAuthorizationRequestAuthenticationConverter
 * @see OAuth2DeviceAuthorizationRequestAuthenticationProvider
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628">OAuth 2.0 Device Authorization Grant</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.1">Section 3.1 Device Authorization Request</a>
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.2">Section 3.2 Device Authorization Response</a>
 */
public final class OAuth2DeviceAuthorizationEndpointFilter extends OncePerRequestFilter {

	private static final String DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI = "/oauth2/device_authorize";

	private static final String DEFAULT_DEVICE_VERIFICATION_URI = "/oauth2/device_verification";

	private final AuthenticationManager authenticationManager;
	private final RequestMatcher deviceAuthorizationEndpointMatcher;
	private final HttpMessageConverter<OAuth2DeviceAuthorizationResponse> deviceAuthorizationHttpResponseConverter =
			new OAuth2DeviceAuthorizationResponseHttpMessageConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
			new OAuth2ErrorHttpMessageConverter();
	private AuthenticationConverter authenticationConverter;
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
			new WebAuthenticationDetailsSource();
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendDeviceAuthorizationResponse;
	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;
	private String verificationUri = DEFAULT_DEVICE_VERIFICATION_URI;

	/**
     * Constructs an {@code OAuth2DeviceAuthorizationEndpointFilter} using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     */
	public OAuth2DeviceAuthorizationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param deviceAuthorizationEndpointUri the endpoint {@code URI} for device authorization requests
	 */
	public OAuth2DeviceAuthorizationEndpointFilter(AuthenticationManager authenticationManager, String deviceAuthorizationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(deviceAuthorizationEndpointUri, "deviceAuthorizationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.deviceAuthorizationEndpointMatcher = new AntPathRequestMatcher(deviceAuthorizationEndpointUri,
				HttpMethod.POST.name());
		this.authenticationConverter = new OAuth2DeviceAuthorizationRequestAuthenticationConverter();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.deviceAuthorizationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthenticationToken =
					(OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationConverter.convert(request);
			deviceAuthorizationRequestAuthenticationToken.setDetails(
					this.authenticationDetailsSource.buildDetails(request));

			OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthenticationTokenResult =
					(OAuth2DeviceAuthorizationRequestAuthenticationToken) this.authenticationManager.authenticate(
							deviceAuthorizationRequestAuthenticationToken);

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response,
					deviceAuthorizationRequestAuthenticationTokenResult);
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Device authorization request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Device Authorization Request from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2DeviceAuthorizationRequestAuthenticationToken} used for authenticating the request.
	 *
	 * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract a DeviceAuthorization Request from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}.
	 *
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}
	 */
	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * and returning the Device Authorization Response.
	 *
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2DeviceAuthorizationRequestAuthenticationToken}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Sets the end-user verification {@code URI} on the authorization server.
	 *
	 * @param verificationUri the end-user verification {@code URI} on the authorization server
	 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628#section-3.2">Section 3.2 Device Authorization Response</a>
	 */
	public void setVerificationUri(String verificationUri) {
		Assert.hasText(verificationUri, "verificationUri cannot be empty");
		this.verificationUri = verificationUri;
	}

	private void sendDeviceAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthenticationToken =
				(OAuth2DeviceAuthorizationRequestAuthenticationToken) authentication;

		OAuth2DeviceCode deviceCode = deviceAuthorizationRequestAuthenticationToken.getDeviceCode();
		OAuth2UserCode userCode = deviceAuthorizationRequestAuthenticationToken.getUserCode();

		// Generate the fully-qualified verification URI
		String issuerUri = AuthorizationServerContextHolder.getContext().getIssuer();
		UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(issuerUri)
				.path(this.verificationUri);
		String verificationUri = uriComponentsBuilder.build().toUriString();
		// @formatter:off
		String verificationUriComplete = uriComponentsBuilder
				.queryParam(OAuth2ParameterNames.USER_CODE, userCode.getTokenValue())
				.build().toUriString();
		// @formatter:on

		// @formatter:off
		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse =
				OAuth2DeviceAuthorizationResponse.with(deviceCode, userCode)
						.verificationUri(verificationUri)
						.verificationUriComplete(verificationUriComplete)
						.build();
		// @formatter:on

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.deviceAuthorizationHttpResponseConverter.write(deviceAuthorizationResponse, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {

		OAuth2Error error = ((OAuth2AuthenticationException) authenticationException).getError();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

}


