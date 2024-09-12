/*
 * Copyright 2020-2024 the original author or authors.
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
package sample.redis.entity;

import java.util.Set;

public class OAuth2ClientCredentialsGrantAuthorization extends OAuth2AuthorizationGrantAuthorization {

	// @fold:on
	public OAuth2ClientCredentialsGrantAuthorization(String id, String registeredClientId, String principalName,
			Set<String> authorizedScopes, AccessToken accessToken) {
		super(id, registeredClientId, principalName, authorizedScopes, accessToken, null);
	}
	// @fold:off

}
