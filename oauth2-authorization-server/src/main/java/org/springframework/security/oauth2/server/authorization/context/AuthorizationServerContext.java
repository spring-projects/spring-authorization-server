/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.context;

import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * A context that holds information of the Authorization Server runtime environment.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerSettings
 * @see AuthorizationServerContextHolder
 */
public interface AuthorizationServerContext {

	/**
	 * Returns the {@code URL} of the Authorization Server's issuer identifier.
	 *
	 * @return the {@code URL} of the Authorization Server's issuer identifier
	 */
	String getIssuer();

	/**
	 * Returns the {@link AuthorizationServerSettings}.
	 *
	 * @return the {@link AuthorizationServerSettings}
	 */
	AuthorizationServerSettings getAuthorizationServerSettings();

}
