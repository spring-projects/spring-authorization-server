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

package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.oauth2.core.Version;
import org.springframework.util.Assert;

import java.io.Serializable;


/**
 * TODO
 * This class is temporary and will be removed after upgrading to Spring Security 5.5.0 GA.
 *
 * The {@code code_challenge_method} is consumed by the authorization endpoint. The client sets
 * the {@code code_challenge_method} parameter and a {@code code_challenge} derived from the
 * {@code code_verifier} using the {@code code_challenge_method}.
 *
 * <p>
 * The {@code code_challenge_method} parameter value may be one of &quot;S256&quot; or
 * &quot;plain&quot;. If the client is capable of using &quot;S256&quot;, it MUST use
 * &quot;S256&quot;, as it is mandatory to implement on the server.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.1
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636#section-6.2">6.2. PKCE Code Challenge Method Registry</a>
 */
public final class PkceCodeChallengeMethod2 implements Serializable {

	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

	public static final PkceCodeChallengeMethod2 S256 = new PkceCodeChallengeMethod2("S256");

	public static final PkceCodeChallengeMethod2 PLAIN = new PkceCodeChallengeMethod2("plain");

	private final String value;

	private PkceCodeChallengeMethod2(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.value = value;
	}

	/**
	 * Returns the value of the authorization response type.
	 *
	 * @return the value of the authorization response type
	 */
	public String getValue() {
		return this.value;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		PkceCodeChallengeMethod2 that = (PkceCodeChallengeMethod2) obj;
		return this.getValue().equals(that.getValue());
	}

	@Override
	public int hashCode() {
		return this.getValue().hashCode();
	}
}
