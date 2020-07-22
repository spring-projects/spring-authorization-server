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

import org.springframework.security.core.SpringSecurityCoreVersion2;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * @author Joe Grandja
 */
public final class TokenType implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion2.SERIAL_VERSION_UID;
	public static final TokenType ACCESS_TOKEN = new TokenType("access_token");
	public static final TokenType AUTHORIZATION_CODE = new TokenType("authorization_code");
	private final String value;

	public TokenType(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.value = value;
	}

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
		TokenType that = (TokenType) obj;
		return this.getValue().equals(that.getValue());
	}

	@Override
	public int hashCode() {
		return this.getValue().hashCode();
	}
}
