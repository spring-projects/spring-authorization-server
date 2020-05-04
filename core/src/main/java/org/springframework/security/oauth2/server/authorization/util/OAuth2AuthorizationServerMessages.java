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
package org.springframework.security.oauth2.server.authorization.util;

/**
 * @author Paurav Munshi
 * @since 0.0.1
 */
public final class OAuth2AuthorizationServerMessages {

	public static final String REQUEST_MISSING_CLIENT_ID = "Request does not contain client id parameter";
	public static final String CLIENT_ID_UNAUTHORIZED_FOR_CODE = "The provided client is not authorized to request authorization code";
	public static final String RESPONSE_TYPE_MISSING_OR_INVALID = "Response type should be present and it should be 'code'";
	public static final String CLIENT_ID_NOT_FOUND = "Can't validate the client id provided with the request";
	public static final String USER_NOT_AUTHENTICATED = "User must be authenticated to perform this action";
	public static final String REDIRECT_URI_MANDATORY_FOR_CLIENT = "Client is configured with multiple URIs. So a specific redirect uri must be supplied with request";

}
