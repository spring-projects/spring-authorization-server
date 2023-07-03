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

import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

public class CustomCodeGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private final String code;

	public CustomCodeGrantAuthenticationToken(String code, Authentication clientPrincipal,
			@Nullable Map<String, Object> additionalParameters) {
		super(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:custom_code"),
				clientPrincipal, additionalParameters);
		Assert.hasText(code, "code cannot be empty");
		this.code = code;
	}

	public String getCode() {
		return this.code;
	}

}
