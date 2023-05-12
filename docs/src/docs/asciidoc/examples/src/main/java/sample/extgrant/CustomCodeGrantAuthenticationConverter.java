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
package sample.extgrant;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

public class CustomCodeGrantAuthenticationConverter implements AuthenticationConverter {

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		// grant_type (REQUIRED)
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!"urn:ietf:params:oauth:grant-type:custom_code".equals(grantType)) { // <1>
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = getParameters(request);

		// code (REQUIRED)
		String code = parameters.getFirst(OAuth2ParameterNames.CODE); // <2>
		if (!StringUtils.hasText(code) ||
				parameters.get(OAuth2ParameterNames.CODE).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
					!key.equals(OAuth2ParameterNames.CLIENT_ID) &&
					!key.equals(OAuth2ParameterNames.CODE)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		return new CustomCodeGrantAuthenticationToken(code, clientPrincipal, additionalParameters); // <3>
	}

	// @fold:on
	private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
		parameterMap.forEach((key, values) -> {
			if (values.length > 0) {
				for (String value : values) {
					parameters.add(key, value);
				}
			}
		});
		return parameters;
	}
	// @fold:off

}
