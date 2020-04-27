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

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Represents a collection of attributes which describe an OAuth 2.0 authorization context.
 *
 * @author Joe Grandja
 * @author Krisztian Toth
 */
public class OAuth2Authorization {
	private String registeredClientId;
	private String principalName;
	private OAuth2AccessToken accessToken;
	private Map<String, Object> attributes;

	protected OAuth2Authorization() {
	}

	public String getRegisteredClientId() {
		return this.registeredClientId;
	}

	public String getPrincipalName() {
		return this.principalName;
	}

	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}

	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns an attribute with the provided name or {@code null} if not found.
	 *
	 * @param name the name of the attribute
	 * @param <T>  the type of the attribute
	 * @return the found attribute or {@code null}
	 */
	public <T> T getAttribute(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) this.attributes.get(name);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		OAuth2Authorization that = (OAuth2Authorization) o;
		return Objects.equals(this.registeredClientId, that.registeredClientId) &&
				Objects.equals(this.principalName, that.principalName) &&
				Objects.equals(this.accessToken, that.accessToken) &&
				Objects.equals(this.attributes, that.attributes);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.registeredClientId, this.principalName, this.accessToken, this.attributes);
	}

	/**
	 * Returns an empty {@link Builder}.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@link OAuth2Authorization}.
	 *
	 * @param authorization the {@link OAuth2Authorization} to copy from
	 * @return the {@link Builder}
	 */
	public static Builder withAuthorization(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		return new Builder(authorization);
	}

	/**
	 * Builder class for {@link OAuth2Authorization}.
	 */
	public static class Builder {
		private String registeredClientId;
		private String principalName;
		private OAuth2AccessToken accessToken;
		private Map<String, Object> attributes = new HashMap<>();

		protected Builder() {
		}

		protected Builder(OAuth2Authorization authorization) {
			this.registeredClientId = authorization.registeredClientId;
			this.principalName = authorization.principalName;
			this.accessToken = authorization.accessToken;
			this.attributes = authorization.attributes;
		}

		/**
		 * Sets the registered client identifier.
		 *
		 * @param registeredClientId the client id
		 * @return the {@link Builder}
		 */
		public Builder registeredClientId(String registeredClientId) {
			this.registeredClientId = registeredClientId;
			return this;
		}

		/**
		 * Sets the principal name.
		 *
		 * @param principalName the principal name
		 * @return the {@link Builder}
		 */
		public Builder principalName(String principalName) {
			this.principalName = principalName;
			return this;
		}

		/**
		 * Sets the {@link OAuth2AccessToken}.
		 *
		 * @param accessToken the {@link OAuth2AccessToken}
		 * @return the {@link Builder}
		 */
		public Builder accessToken(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			return this;
		}

		/**
		 * Adds the attribute with the specified name and {@link String} value to the attributes map.
		 *
		 * @param name  the name of the attribute
		 * @param value the value of the attribute
		 * @return the {@link Builder}
		 */
		public Builder attribute(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.hasText(value, "value cannot be empty");
			this.attributes.put(name, value);
			return this;
		}

		/**
		 * A {@code Consumer} of the attributes map allowing to access or modify its content.
		 *
		 * @param attributesConsumer a {@link Consumer} of the attributes map
		 * @return the {@link Builder}
		 */
		public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
			attributesConsumer.accept(this.attributes);
			return this;
		}

		/**
		 * Builds a new {@link OAuth2Authorization}.
		 *
		 * @return the {@link OAuth2Authorization}
		 */
		public OAuth2Authorization build() {
			Assert.hasText(this.registeredClientId, "registeredClientId cannot be empty");
			Assert.hasText(this.principalName, "principalName cannot be empty");
			if (this.accessToken == null && this.attributes.get(TokenType.AUTHORIZATION_CODE.getValue()) == null) {
				throw new IllegalArgumentException("either accessToken has to be set or the authorization code with key '"
						+ TokenType.AUTHORIZATION_CODE.getValue() + "' must be provided in the attributes map");
			}
			return create();
		}

		private OAuth2Authorization create() {
			OAuth2Authorization oAuth2Authorization = new OAuth2Authorization();
			oAuth2Authorization.registeredClientId = this.registeredClientId;
			oAuth2Authorization.principalName = this.principalName;
			oAuth2Authorization.accessToken = this.accessToken;
			oAuth2Authorization.attributes = Collections.unmodifiableMap(this.attributes);
			return oAuth2Authorization;
		}
	}
}
