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

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

/**
 * @author Paurav Munshi
 * @since 0.0.1
 * @see Converter
 */
public class OAuth2AuthorizationRequestConverter implements Converter<HttpServletRequest, OAuth2AuthorizationRequest> {

	@Override
	public OAuth2AuthorizationRequest convert(HttpServletRequest request) {
		String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
		Set<String> scopes = !StringUtils.isEmpty(scope)
				? new LinkedHashSet<String>(Arrays.asList(scope.split(" ")))
				: Collections.emptySet();

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId(request.getParameter(OAuth2ParameterNames.CLIENT_ID))
				.redirectUri(request.getParameter(OAuth2ParameterNames.REDIRECT_URI))
				.scopes(scopes)
				.state(request.getParameter(OAuth2ParameterNames.STATE))
				.authorizationUri(request.getServletPath())
				.build();

		return authorizationRequest;
	}

}
