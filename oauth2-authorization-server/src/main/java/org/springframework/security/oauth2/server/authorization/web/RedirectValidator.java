/*
 * Copyright 2020-2021 the original author or authors.
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

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Implementations of this interface are responsible for validating the redirect URI for OAuth 2.0 client.
 *
 * @author Anoop Garlapati
 * @since 0.1.1
 */
@FunctionalInterface
public interface RedirectValidator {

	/**
	 * Validates the requested redirect URI for the specified {@link RegisteredClient}.
	 *
	 * @param requestedRedirectUri the redirect URI that was requested
	 * @param registeredClient the client for which the redirect URI is being validated
	 * @return true if the requestedRedirectUri is valid
	 */
	boolean validate(String requestedRedirectUri, RegisteredClient registeredClient);
}
