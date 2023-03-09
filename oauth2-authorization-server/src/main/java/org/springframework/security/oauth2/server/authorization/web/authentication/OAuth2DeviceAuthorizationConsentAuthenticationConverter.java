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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2DeviceVerificationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Authorization Consent from {@link HttpServletRequest}
 * for the OAuth 2.0 Device Authorization Grant and then converts it to an
 * {@link OAuth2DeviceAuthorizationConsentAuthenticationToken} used for
 * authenticating the request.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see AuthenticationConverter
 * @see OAuth2DeviceAuthorizationConsentAuthenticationToken
 * @see OAuth2DeviceVerificationEndpointFilter
 */
public final class OAuth2DeviceAuthorizationConsentAuthenticationConverter implements AuthenticationConverter {

	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final String DEVICE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc8628#section-3.3";
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!"POST".equals(request.getMethod())) {
			return null;
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		String authorizationUri = request.getRequestURL().toString();

		// user_code (REQUIRED)
		String userCode = parameters.getFirst(OAuth2ParameterNames.USER_CODE);
		if (!StringUtils.hasText(userCode) || parameters.get(OAuth2ParameterNames.USER_CODE).size() != 1) {
			OAuth2EndpointUtils.throwError(
					OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.USER_CODE,
					DEVICE_ERROR_URI);
		}

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID, DEFAULT_ERROR_URI);
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		// state (REQUIRED)
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		if (!StringUtils.hasText(state) || parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
			OAuth2EndpointUtils.throwError(
					OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.STATE,
					DEFAULT_ERROR_URI);
		}

		// scope (OPTIONAL)
		Set<String> scopes = null;
		if (parameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			scopes = new HashSet<>(parameters.get(OAuth2ParameterNames.SCOPE));
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.CLIENT_ID) &&
					!key.equals(OAuth2ParameterNames.STATE) &&
					!key.equals(OAuth2ParameterNames.SCOPE) &&
					!key.equals(OAuth2ParameterNames.USER_CODE)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		return new OAuth2DeviceAuthorizationConsentAuthenticationToken(authorizationUri, clientId, principal,
				OAuth2EndpointUtils.normalizeUserCode(userCode), state, scopes, additionalParameters);
	}

}
