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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * A representation of an OAuth 2.0 Authorization,
 * which holds state related to the authorization granted to the {@link #getRegisteredClientId() client}
 * by the {@link #getPrincipalName() resource owner}.
 *
 * @author Joe Grandja
 * @author Krisztian Toth
 * @since 0.0.1
 * @see RegisteredClient
 * @see OAuth2Tokens
 */
public class OAuth2Authorization implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private String registeredClientId;
	private String principalName;
	private OAuth2Tokens tokens;

	@Deprecated
	private OAuth2AccessToken accessToken;

	private Map<String, Object> attributes;

	protected OAuth2Authorization() {
	}

	/**
	 * Returns the identifier for the {@link RegisteredClient#getId() registered client}.
	 *
	 * @return the {@link RegisteredClient#getId()}
	 */
	public String getRegisteredClientId() {
		return this.registeredClientId;
	}

	/**
	 * Returns the resource owner's {@code Principal} name.
	 *
	 * @return the resource owner's {@code Principal} name
	 */
	public String getPrincipalName() {
		return this.principalName;
	}

	/**
	 * Returns the {@link OAuth2Tokens}.
	 *
	 * @return the {@link OAuth2Tokens}
	 */
	public OAuth2Tokens getTokens() {
		return this.tokens;
	}

	/**
	 * Returns the {@link OAuth2AccessToken access token} credential.
	 *
	 * @return the {@link OAuth2AccessToken}
	 */
	@Deprecated
	public OAuth2AccessToken getAccessToken() {
		return getTokens().getAccessToken();
	}

	/**
	 * Returns the attribute(s) associated to the authorization.
	 *
	 * @return a {@code Map} of the attribute(s)
	 */
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the value of an attribute associated to the authorization.
	 *
	 * @param name the name of the attribute
	 * @param <T> the type of the attribute
	 * @return the value of the attribute associated to the authorization, or {@code null} if not available
	 */
	@SuppressWarnings("unchecked")
	public <T> T getAttribute(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) this.attributes.get(name);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OAuth2Authorization that = (OAuth2Authorization) obj;
		return Objects.equals(this.registeredClientId, that.registeredClientId) &&
				Objects.equals(this.principalName, that.principalName) &&
				Objects.equals(this.tokens, that.tokens) &&
				Objects.equals(this.attributes, that.attributes);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.registeredClientId, this.principalName, this.tokens, this.attributes);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@link RegisteredClient#getId()}.
	 *
	 * @param registeredClient the {@link RegisteredClient}
	 * @return the {@link Builder}
	 */
	public static Builder withRegisteredClient(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		return new Builder(registeredClient.getId());
	}

	/**
	 * Returns a new {@link Builder}, initialized with the values from the provided {@code authorization}.
	 *
	 * @param authorization the authorization used for initializing the {@link Builder}
	 * @return the {@link Builder}
	 */
	public static Builder from(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		return new Builder(authorization.getRegisteredClientId())
				.principalName(authorization.getPrincipalName())
				.tokens(OAuth2Tokens.from(authorization.getTokens()).build())
				.attributes(attrs -> attrs.putAll(authorization.getAttributes()));
	}

	/**
	 * A builder for {@link OAuth2Authorization}.
	 */
	public static class Builder implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		private String registeredClientId;
		private String principalName;
		private OAuth2Tokens tokens;

		@Deprecated
		private OAuth2AccessToken accessToken;

		private Map<String, Object> attributes = new HashMap<>();

		protected Builder(String registeredClientId) {
			this.registeredClientId = registeredClientId;
		}

		/**
		 * Sets the resource owner's {@code Principal} name.
		 *
		 * @param principalName the resource owner's {@code Principal} name
		 * @return the {@link Builder}
		 */
		public Builder principalName(String principalName) {
			this.principalName = principalName;
			return this;
		}

		/**
		 * Sets the {@link OAuth2Tokens}.
		 *
		 * @param tokens the {@link OAuth2Tokens}
		 * @return the {@link Builder}
		 */
		public Builder tokens(OAuth2Tokens tokens) {
			this.tokens = tokens;
			return this;
		}

		/**
		 * Sets the {@link OAuth2AccessToken access token} credential.
		 *
		 * @param accessToken the {@link OAuth2AccessToken}
		 * @return the {@link Builder}
		 */
		@Deprecated
		public Builder accessToken(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			return this;
		}

		/**
		 * Adds an attribute associated to the authorization.
		 *
		 * @param name the name of the attribute
		 * @param value the value of the attribute
		 * @return the {@link Builder}
		 */
		public Builder attribute(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.attributes.put(name, value);
			return this;
		}

		/**
		 * A {@code Consumer} of the attributes {@code Map}
		 * allowing the ability to add, replace, or remove.
		 *
		 * @param attributesConsumer a {@link Consumer} of the attributes {@code Map}
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
			Assert.hasText(this.principalName, "principalName cannot be empty");

			OAuth2Authorization authorization = new OAuth2Authorization();
			authorization.registeredClientId = this.registeredClientId;
			authorization.principalName = this.principalName;
			if (this.tokens == null) {
				OAuth2Tokens.Builder builder = OAuth2Tokens.builder();
				if (this.accessToken != null) {
					builder.accessToken(this.accessToken);
				}
				this.tokens = builder.build();
			}
			authorization.tokens = this.tokens;
			authorization.attributes = Collections.unmodifiableMap(this.attributes);
			return authorization;
		}
	}
}
