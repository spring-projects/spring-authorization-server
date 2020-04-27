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

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Converts from {@link HttpServletRequest} to {@link OAuth2ClientAuthenticationToken} that can be authenticated.
 *
 * @author Patryk Kostrzewa
 */
public class DefaultOAuth2ClientAuthenticationConverter implements AuthenticationConverter {

	private static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

	@Override
	public OAuth2ClientAuthenticationToken convert(HttpServletRequest request) {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (header == null) {
			return null;
		}

		header = header.trim();
		if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
			return null;
		}

		if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}

		byte[] decoded;
		try {
			byte[] base64Token = header.substring(6)
					.getBytes(StandardCharsets.UTF_8);
			decoded = Base64.getDecoder()
					.decode(base64Token);
		} catch (IllegalArgumentException e) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}

		String token = new String(decoded, StandardCharsets.UTF_8);
		String[] credentials = token.split(":");
		if (credentials.length != 2) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		}
		return new OAuth2ClientAuthenticationToken(credentials[0], credentials[1]);
	}
}
