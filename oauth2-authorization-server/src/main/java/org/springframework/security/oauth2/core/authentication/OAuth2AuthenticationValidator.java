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
package org.springframework.security.oauth2.core.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/**
 * Implementations of this interface are responsible for validating the attribute(s)
 * of the {@link Authentication} associated to the {@link OAuth2AuthenticationContext}.
 *
 * @author Joe Grandja
 * @since 0.2.0
 * @see OAuth2AuthenticationContext
 */
@FunctionalInterface
public interface OAuth2AuthenticationValidator {

	/**
	 * Validate the attribute(s) of the {@link Authentication}.
	 *
	 * @param authenticationContext the authentication context
	 * @throws OAuth2AuthenticationException if the attribute(s) of the {@code Authentication} is invalid
	 */
	void validate(OAuth2AuthenticationContext authenticationContext) throws OAuth2AuthenticationException;

}
