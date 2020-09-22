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
package org.springframework.security.oauth2.server.authorization;


import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

/**
 * The name of the attributes that may be contained in the
 * {@link OAuth2Authorization#getAttributes()} {@code Map}.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2Authorization#getAttributes()
 */
public interface OAuth2AuthorizationAttributeNames {

	/**
	 * The name of the attribute used for correlating the user consent request/response.
	 */
	String STATE = OAuth2Authorization.class.getName().concat(".STATE");

	/**
	 * The name of the attribute used for the {@link OAuth2ParameterNames#CODE} parameter.
	 */
	String CODE = OAuth2Authorization.class.getName().concat(".CODE");

	/**
	 * The name of the attribute used for the {@link OAuth2AuthorizationRequest}.
	 */
	String AUTHORIZATION_REQUEST = OAuth2Authorization.class.getName().concat(".AUTHORIZATION_REQUEST");

	/**
	 * The name of the attribute used for the authorized scope(s).
	 */
	String AUTHORIZED_SCOPES = OAuth2Authorization.class.getName().concat(".AUTHORIZED_SCOPES");

	/**
	 * The name of the attribute used for the attributes/claims of the {@link OAuth2AccessToken}.
	 */
	String ACCESS_TOKEN_ATTRIBUTES = OAuth2Authorization.class.getName().concat(".ACCESS_TOKEN_ATTRIBUTES");

}
