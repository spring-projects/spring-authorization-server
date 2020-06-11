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
package org.springframework.security.oauth2.server.authorization.jose;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Implementations of this interface are responsible for &quot;encoding&quot;
 * a JSON Web Token (JWT) from it's unsecured representation {@link UnsecuredJwt}
 * to secured representation {@link Jwt}.
 *
 * @author Anoop Garlapati
 * @since 0.0.1
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 */
@FunctionalInterface
public interface JwtEncoder {

	/**
	 * Encodes the JWT from its unsecured format {@link UnsecuredJwt} and returns a {@link Jwt}.
	 *
	 * @param unsecuredJwt the unsecured JWT representation
	 * @return a {@link Jwt}
	 * @throws JwtException if an exception occurs while attempting to encode the JWT
	 */
	Jwt encode(UnsecuredJwt unsecuredJwt) throws JwtException;
}
