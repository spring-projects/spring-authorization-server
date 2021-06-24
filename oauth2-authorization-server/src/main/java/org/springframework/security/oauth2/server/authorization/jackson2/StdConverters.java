/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.util.StdConverter;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * {@code StdConverter} implementations.
 *
 * @author Joe Grandja
 * @since 0.1.2
 */
abstract class StdConverters {

	static final class AuthorizationGrantTypeConverter extends StdConverter<JsonNode, AuthorizationGrantType> {

		@Override
		public AuthorizationGrantType convert(JsonNode jsonNode) {
			String value = JsonNodeUtils.findStringValue(jsonNode, "value");
			if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.AUTHORIZATION_CODE;
			}
			if (AuthorizationGrantType.IMPLICIT.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.IMPLICIT;
			}
			if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.CLIENT_CREDENTIALS;
			}
			if (AuthorizationGrantType.PASSWORD.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.PASSWORD;
			}
			return null;
		}

	}

}
