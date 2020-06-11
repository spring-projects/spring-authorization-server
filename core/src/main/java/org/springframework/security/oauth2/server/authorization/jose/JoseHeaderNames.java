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

/**
 * The Registered Header Parameter Names defined by the JSON Web Signature (JWS) specification
 * that may be contained in the JSON object JOSE Header.
 *
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-4.1">JWS Headers</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7797#section-3">B64 Header Parameter</a>
 */
public interface JoseHeaderNames {

	String ALG = "alg";

	String JKU = "jku";

	String JWK = "jwk";

	String KID = "kid";

	String X5U = "x5u";

	String X5C = "x5c";

	String X5T = "x5t";

	String X5T256 = "x5t#256";

	String TYP = "typ";

	String CTY = "cty";

	String CRIT = "crit";

	String B64 = "b64";
}
