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
package org.springframework.security.oauth2.server.authorization.token;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A container for OAuth 2.0 Tokens.
 *
 * @author Joe Grandja
 * @since 0.0.3
 * @see OAuth2Authorization
 * @see OAuth2TokenMetadata
 * @see AbstractOAuth2Token
 * @see OAuth2AccessToken
 * @see OAuth2RefreshToken
 */
public class OAuth2Tokens implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens;

	protected OAuth2Tokens(Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens) {
		this.tokens = new HashMap<>(tokens);
	}

	/**
	 * Returns the {@link OAuth2AccessToken access token}.
	 *
	 * @return the {@link OAuth2AccessToken}, or {@code null} if not available
	 */
	@Nullable
	public OAuth2AccessToken getAccessToken() {
		return getToken(OAuth2AccessToken.class);
	}

	/**
	 * Returns the {@link OAuth2RefreshToken refresh token}.
	 *
	 * @return the {@link OAuth2RefreshToken}, or {@code null} if not available
	 */
	@Nullable
	public OAuth2RefreshToken getRefreshToken() {
		return getToken(OAuth2RefreshToken.class);
	}

	/**
	 * Returns the token specified by {@code tokenType}.
	 *
	 * @param tokenType the token type
	 * @param <T> the type of the token
	 * @return the token, or {@code null} if not available
	 */
	@Nullable
	@SuppressWarnings("unchecked")
	public <T extends AbstractOAuth2Token> T getToken(Class<T> tokenType) {
		Assert.notNull(tokenType, "tokenType cannot be null");
		OAuth2TokenHolder tokenHolder = this.tokens.get(tokenType);
		return tokenHolder != null ? (T) tokenHolder.getToken() : null;
	}

	/**
	 * Returns the token specified by {@code token}.
	 *
	 * @param token the token
	 * @param <T> the type of the token
	 * @return the token, or {@code null} if not available
	 */
	@Nullable
	@SuppressWarnings("unchecked")
	public <T extends AbstractOAuth2Token> T getToken(String token) {
		Assert.hasText(token, "token cannot be empty");
		OAuth2TokenHolder tokenHolder = this.tokens.values().stream()
				.filter(holder -> holder.getToken().getTokenValue().equals(token))
				.findFirst()
				.orElse(null);
		return tokenHolder != null ? (T) tokenHolder.getToken() : null;
	}

	/**
	 * Returns the token metadata associated to the provided {@code token}.
	 *
	 * @param token the token
	 * @param <T> the type of the token
	 * @return the token metadata, or {@code null} if not available
	 */
	@Nullable
	public <T extends AbstractOAuth2Token> OAuth2TokenMetadata getTokenMetadata(T token) {
		Assert.notNull(token, "token cannot be null");
		OAuth2TokenHolder tokenHolder = this.tokens.get(token.getClass());
		return (tokenHolder != null && tokenHolder.getToken().equals(token)) ?
				tokenHolder.getTokenMetadata() : null;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OAuth2Tokens that = (OAuth2Tokens) obj;
		return Objects.equals(this.tokens, that.tokens);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.tokens);
	}

	/**
	 * Returns a new {@link Builder}.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Returns a new {@link Builder}, initialized with the values from the provided {@code tokens}.
	 *
	 * @param tokens the tokens used for initializing the {@link Builder}
	 * @return the {@link Builder}
	 */
	public static Builder from(OAuth2Tokens tokens) {
		Assert.notNull(tokens, "tokens cannot be null");
		return new Builder(tokens.tokens);
	}

	/**
	 * A builder for {@link OAuth2Tokens}.
	 */
	public static class Builder implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		private Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens;

		protected Builder() {
			this.tokens = new HashMap<>();
		}

		protected Builder(Map<Class<? extends AbstractOAuth2Token>, OAuth2TokenHolder> tokens) {
			this.tokens = new HashMap<>(tokens);
		}

		/**
		 * Sets the {@link OAuth2AccessToken access token}.
		 *
		 * @param accessToken the {@link OAuth2AccessToken}
		 * @return the {@link Builder}
		 */
		public Builder accessToken(OAuth2AccessToken accessToken) {
			return addToken(accessToken, null);
		}

		/**
		 * Sets the {@link OAuth2AccessToken access token} and associated {@link OAuth2TokenMetadata token metadata}.
		 *
		 * @param accessToken the {@link OAuth2AccessToken}
		 * @param tokenMetadata the {@link OAuth2TokenMetadata}
		 * @return the {@link Builder}
		 */
		public Builder accessToken(OAuth2AccessToken accessToken, OAuth2TokenMetadata tokenMetadata) {
			return addToken(accessToken, tokenMetadata);
		}

		/**
		 * Sets the {@link OAuth2RefreshToken refresh token}.
		 *
		 * @param refreshToken the {@link OAuth2RefreshToken}
		 * @return the {@link Builder}
		 */
		public Builder refreshToken(OAuth2RefreshToken refreshToken) {
			return addToken(refreshToken, null);
		}

		/**
		 * Sets the {@link OAuth2RefreshToken refresh token} and associated {@link OAuth2TokenMetadata token metadata}.
		 *
		 * @param refreshToken the {@link OAuth2RefreshToken}
		 * @param tokenMetadata the {@link OAuth2TokenMetadata}
		 * @return the {@link Builder}
		 */
		public Builder refreshToken(OAuth2RefreshToken refreshToken, OAuth2TokenMetadata tokenMetadata) {
			return addToken(refreshToken, tokenMetadata);
		}

		/**
		 * Sets the token.
		 *
		 * @param token the token
		 * @param <T> the type of the token
		 * @return the {@link Builder}
		 */
		public <T extends AbstractOAuth2Token> Builder token(T token) {
			return addToken(token, null);
		}

		/**
		 * Sets the token and associated {@link OAuth2TokenMetadata token metadata}.
		 *
		 * @param token the token
		 * @param tokenMetadata the {@link OAuth2TokenMetadata}
		 * @param <T> the type of the token
		 * @return the {@link Builder}
		 */
		public <T extends AbstractOAuth2Token> Builder token(T token, OAuth2TokenMetadata tokenMetadata) {
			return addToken(token, tokenMetadata);
		}

		protected Builder addToken(AbstractOAuth2Token token, OAuth2TokenMetadata tokenMetadata) {
			Assert.notNull(token, "token cannot be null");
			if (tokenMetadata == null) {
				tokenMetadata = OAuth2TokenMetadata.builder().build();
			}
			this.tokens.put(token.getClass(), new OAuth2TokenHolder(token, tokenMetadata));
			return this;
		}

		/**
		 * Builds a new {@link OAuth2Tokens}.
		 *
		 * @return the {@link OAuth2Tokens}
		 */
		public OAuth2Tokens build() {
			return new OAuth2Tokens(this.tokens);
		}
	}

	protected static class OAuth2TokenHolder implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		private final AbstractOAuth2Token token;
		private final OAuth2TokenMetadata tokenMetadata;

		protected OAuth2TokenHolder(AbstractOAuth2Token token, OAuth2TokenMetadata tokenMetadata) {
			this.token = token;
			this.tokenMetadata = tokenMetadata;
		}

		protected AbstractOAuth2Token getToken() {
			return this.token;
		}

		protected OAuth2TokenMetadata getTokenMetadata() {
			return this.tokenMetadata;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || getClass() != obj.getClass()) {
				return false;
			}
			OAuth2TokenHolder that = (OAuth2TokenHolder) obj;
			return Objects.equals(this.token, that.token) &&
					Objects.equals(this.tokenMetadata, that.tokenMetadata);
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.token, this.tokenMetadata);
		}
	}
}
