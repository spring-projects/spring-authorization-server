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
package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * A representation of a client registration with an OAuth 2.0 Authorization Server.
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2 Client Registration</a>
 */
public class RegisteredClient implements Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private String id;
	private String clientId;
	private String clientSecret;
	private Set<ClientAuthenticationMethod> clientAuthenticationMethods =
			Collections.singleton(ClientAuthenticationMethod.BASIC);
	private Set<AuthorizationGrantType> authorizationGrantTypes = Collections.emptySet();
	private Set<String> redirectUris = Collections.emptySet();
	private Set<String> scopes = Collections.emptySet();

	protected RegisteredClient() {
	}

	/**
	 * Returns the identifier for the registration.
	 *
	 * @return the identifier for the registration
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * Returns the client identifier.
	 *
	 * @return the client identifier
	 */
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Returns the client secret.
	 *
	 * @return the client secret
	 */
	public String getClientSecret() {
		return this.clientSecret;
	}

	/**
	 * Returns the {@link ClientAuthenticationMethod authentication method(s)} used
	 * when authenticating the client with the authorization server.
	 *
	 * @return the {@code Set} of {@link ClientAuthenticationMethod authentication method(s)}
	 */
	public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
		return this.clientAuthenticationMethods;
	}

	/**
	 * Returns the {@link AuthorizationGrantType authorization grant type(s)} that the client may use.
	 *
	 * @return the {@code Set} of {@link AuthorizationGrantType authorization grant type(s)}
	 */
	public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
		return this.authorizationGrantTypes;
	}

	/**
	 * Returns the redirect URI(s) that the client may use in redirect-based flows.
	 *
	 * @return the {@code Set} of redirect URI(s)
	 */
	public Set<String> getRedirectUris() {
		return this.redirectUris;
	}

	/**
	 * Returns the scope(s) used by the client.
	 *
	 * @return the {@code Set} of scope(s)
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	@Override
	public String toString() {
		return "RegisteredClient{" +
				"id='" + this.id + '\'' +
				", clientId='" + this.clientId + '\'' +
				", clientAuthenticationMethods=" + this.clientAuthenticationMethods +
				", authorizationGrantTypes=" + this.authorizationGrantTypes +
				", redirectUris=" + this.redirectUris +
				", scopes=" + this.scopes +
				'}';
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided registration identifier.
	 *
	 * @param id the identifier for the registration
	 * @return the {@link Builder}
	 */
	public static Builder withId(String id) {
		Assert.hasText(id, "id cannot be empty");
		return new Builder(id);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@link RegisteredClient}.
	 *
	 * @param registeredClient the {@link RegisteredClient} to copy from
	 * @return the {@link Builder}
	 */
	public static Builder withRegisteredClient(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		return new Builder(registeredClient);
	}

	/**
	 * A builder for {@link RegisteredClient}.
	 */
	public static class Builder implements Serializable {
		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
		private String id;
		private String clientId;
		private String clientSecret;
		private Set<ClientAuthenticationMethod> clientAuthenticationMethods =
				new LinkedHashSet<>(Collections.singletonList(ClientAuthenticationMethod.BASIC));
		private Set<AuthorizationGrantType> authorizationGrantTypes = new LinkedHashSet<>();
		private Set<String> redirectUris = new LinkedHashSet<>();
		private Set<String> scopes = new LinkedHashSet<>();

		protected Builder(String id) {
			this.id = id;
		}

		protected Builder(RegisteredClient registeredClient) {
			this.id = registeredClient.id;
			this.clientId = registeredClient.clientId;
			this.clientSecret = registeredClient.clientSecret;
			this.clientAuthenticationMethods = registeredClient.clientAuthenticationMethods == null ? null :
					new HashSet<>(registeredClient.clientAuthenticationMethods);
			this.authorizationGrantTypes = registeredClient.authorizationGrantTypes == null ? null :
					new HashSet<>(registeredClient.authorizationGrantTypes);
			this.redirectUris = registeredClient.redirectUris == null ? null :
					new HashSet<>(registeredClient.redirectUris);
			this.scopes = registeredClient.scopes == null ? null : new HashSet<>(registeredClient.scopes);
		}

		/**
		 * Sets the identifier for the registration.
		 *
		 * @param id the identifier for the registration
		 * @return the {@link Builder}
		 */
		public Builder id(String id) {
			this.id = id;
			return this;
		}

		/**
		 * Sets the client identifier.
		 *
		 * @param clientId the client identifier
		 * @return the {@link Builder}
		 */
		public Builder clientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		/**
		 * Sets the client secret.
		 *
		 * @param clientSecret the client secret
		 * @return the {@link Builder}
		 */
		public Builder clientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}

		/**
		 * Adds the {@link ClientAuthenticationMethod authentication method} to the set of
		 * client authentication methods used when authenticating the client with the authorization server.
		 *
		 * @param clientAuthenticationMethod the authentication method
		 * @return the {@link Builder}
		 */
		public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
			this.clientAuthenticationMethods.add(clientAuthenticationMethod);
			return this;
		}

		/**
		 * Sets the {@link ClientAuthenticationMethod authentication method(s)} used
		 * when authenticating the client with the authorization server.
		 *
		 * @param clientAuthenticationMethodsConsumer the authentication method(s) {@link Consumer}
		 * @return the {@link Builder}
		 */
		public Builder clientAuthenticationMethods(
				Consumer<Set<ClientAuthenticationMethod>> clientAuthenticationMethodsConsumer) {
			clientAuthenticationMethodsConsumer.accept(this.clientAuthenticationMethods);
			return this;
		}

		/**
		 * Adds the {@link AuthorizationGrantType authorization grant type} to
		 * the set of authorization grant types that the client may use.
		 *
		 * @param authorizationGrantType the authorization grant type
		 * @return the {@link Builder}
		 */
		public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
			this.authorizationGrantTypes.add(authorizationGrantType);
			return this;
		}

		/**
		 * Sets the {@link AuthorizationGrantType authorization grant type(s)} that the client may use.
		 *
		 * @param authorizationGrantTypesConsumer the authorization grant type(s) {@link Consumer}
		 * @return the {@link Builder}
		 */
		public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> authorizationGrantTypesConsumer) {
			authorizationGrantTypesConsumer.accept(this.authorizationGrantTypes);
			return this;
		}

		/**
		 * Adds the redirect URI to the set of redirect URIs that the client may use in redirect-based flows.
		 *
		 * @param redirectUri the redirect URI to add
		 * @return the {@link Builder}
		 */
		public Builder redirectUri(String redirectUri) {
			this.redirectUris.add(redirectUri);
			return this;
		}

		/**
		 * Sets the redirect URI(s) that the client may use in redirect-based flows.
		 *
		 * @param redirectUrisConsumer the redirect URI(s) {@link Consumer}
		 * @return the {@link Builder}
		 */
		public Builder redirectUris(Consumer<Set<String>> redirectUrisConsumer) {
			redirectUrisConsumer.accept(this.redirectUris);
			return this;
		}

		/**
		 * Adds the scope to the set of scopes used by the client.
		 *
		 * @param scope the scope to add
		 * @return the {@link Builder}
		 */
		public Builder scope(String scope) {
			this.scopes.add(scope);
			return this;
		}

		/**
		 * Sets the scope(s) used by the client.
		 *
		 * @param scopesConsumer the scope(s) {@link Consumer}
		 * @return the {@link Builder}
		 */
		public Builder scopes(Consumer<Set<String>> scopesConsumer) {
			scopesConsumer.accept(this.scopes);
			return this;
		}

		/**
		 * Builds a new {@link RegisteredClient}.
		 *
		 * @return a {@link RegisteredClient}
		 */
		public RegisteredClient build() {
			Assert.notEmpty(this.clientAuthenticationMethods, "clientAuthenticationMethods cannot be empty");
			Assert.notEmpty(this.authorizationGrantTypes, "authorizationGrantTypes cannot be empty");
			if (authorizationGrantTypes.contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
				Assert.hasText(this.id, "id cannot be empty");
				Assert.hasText(this.clientId, "clientId cannot be empty");
				Assert.hasText(this.clientSecret, "clientSecret cannot be empty");
				Assert.notEmpty(this.redirectUris, "redirectUris cannot be empty");
			}
			this.validateScopes();
			this.validateRedirectUris();
			return this.create();
		}

		private RegisteredClient create() {
			RegisteredClient registeredClient = new RegisteredClient();

			registeredClient.id = this.id;
			registeredClient.clientId = this.clientId;
			registeredClient.clientSecret = this.clientSecret;
			registeredClient.clientAuthenticationMethods =
					Collections.unmodifiableSet(this.clientAuthenticationMethods);
			registeredClient.authorizationGrantTypes = Collections.unmodifiableSet(this.authorizationGrantTypes);
			registeredClient.redirectUris = Collections.unmodifiableSet(this.redirectUris);
			registeredClient.scopes = Collections.unmodifiableSet(this.scopes);

			return registeredClient;
		}

		private void validateScopes() {
			if (CollectionUtils.isEmpty(this.scopes)) {
				return;
			}

			for (String scope : this.scopes) {
				Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
			}
		}

		private static boolean validateScope(String scope) {
			return scope == null ||
					scope.chars().allMatch(c -> withinTheRangeOf(c, 0x21, 0x21) ||
							withinTheRangeOf(c, 0x23, 0x5B) ||
							withinTheRangeOf(c, 0x5D, 0x7E));
		}

		private static boolean withinTheRangeOf(int c, int min, int max) {
			return c >= min && c <= max;
		}

		private void validateRedirectUris() {
			if (CollectionUtils.isEmpty(this.redirectUris)) {
				return;
			}

			for (String redirectUri : redirectUris) {
				Assert.isTrue(validateRedirectUri(redirectUri),
						"redirect_uri \"" + redirectUri + "\" is not a valid redirect URI or contains fragment");
			}
		}

		private static boolean validateRedirectUri(String redirectUri) {
			try {
				URI validRedirectUri = new URI(redirectUri);
				return validRedirectUri.getFragment() == null;
			} catch (URISyntaxException ex) {
				return false;
			}
		}
	}

}
