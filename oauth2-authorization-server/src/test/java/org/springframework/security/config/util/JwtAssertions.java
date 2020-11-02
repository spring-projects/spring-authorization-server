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

package org.springframework.security.config.util;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Helper class to assert on a content of string-represented Jwt token.
 *
 * @author Alexey Nesterov
 * @since 0.1.0
 */
public class JwtAssertions {

	private final JwtDecoder jwtDecoder;
	public JwtAssertions(JwtDecoder jwtDecoder) {
		this.jwtDecoder = jwtDecoder;
	}

	public Matcher<String> withClaim(String name, String value) {
		return new BaseMatcher<String>() {
			@Override
			public boolean matches(Object item) {
				String accessToken = item.toString();
				Jwt jwt = jwtDecoder.decode(accessToken);
				return value.equals(jwt.getClaims().get(name));
			}

			@Override
			public void describeTo(Description description) {
				description.appendText(String.format("Valid Jwt token with a claim '%s' with value '%s'", name, value));
			}
		};
	}
}
