/*
 * Copyright 2022 the original author or authors.
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

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientResource;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Support for mapping domain objects to/from resource objects with the ability to customize the mapping process.
 * <p>
 * The following objects are supported:
 *
 * <ul>
 *   <li>{@link RegisteredClient} and {@link RegisteredClientResource}</li>
 *   <li>{@link OAuth2Authorization} and {@link OAuth2AuthorizationResource}</li>
 *   <li>{@link OAuth2AuthorizationConsent} and {@link OAuth2AuthorizationConsentResource}</li>
 * </ul>
 *
 * @author Steve Riesenberg
 * @since 0.2.2
 */
public final class OAuth2AuthorizationServerResourceMappers {

	private static final Map<String, Class<? extends OAuth2Token>> TOKEN_TYPES;
	static {
		Map<String, Class<? extends OAuth2Token>> tokenTypes = new HashMap<>();
		tokenTypes.put(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), OAuth2AuthorizationCode.class);
		tokenTypes.put(OAuth2ParameterNames.ACCESS_TOKEN, OAuth2AccessToken.class);
		tokenTypes.put(OAuth2ParameterNames.REFRESH_TOKEN, OAuth2RefreshToken.class);
		tokenTypes.put(OidcParameterNames.ID_TOKEN, OidcIdToken.class);
		TOKEN_TYPES = Collections.unmodifiableMap(tokenTypes);
	}

	private OAuth2AuthorizationServerResourceMappers() {
	}

	/**
	 * Returns a {@link Function} for mapping a {@link RegisteredClient} to a {@link RegisteredClientResource}.
	 *
	 * @return A {@link Function} for mapping a {@link RegisteredClient} to a {@link RegisteredClientResource}
	 */
	public static Function<RegisteredClient, RegisteredClientResource> registeredClientResourceMapper() {
		return registeredClientResourceMapper(RegisteredClientResource::new);
	}

	/**
	 * Returns a {@link Function} for mapping a {@link RegisteredClient} to a {@link RegisteredClientResource}.
	 *
	 * @param registeredClientResourceSupplier A {@link Supplier} providing a custom object
	 * @return A {@link Function} for mapping a {@link RegisteredClient} to a {@link RegisteredClientResource}
	 */
	public static Function<RegisteredClient, RegisteredClientResource> registeredClientResourceMapper(
			Supplier<RegisteredClientResource> registeredClientResourceSupplier) {
		return (registeredClient) -> {
			Set<String> clientAuthenticationMethods = new HashSet<>();
			registeredClient.getClientAuthenticationMethods().forEach(clientAuthenticationMethod ->
					clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

			Set<String> authorizationGrantTypes = new HashSet<>();
			registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
					authorizationGrantTypes.add(authorizationGrantType.getValue()));

			RegisteredClientResource registeredClientResource = registeredClientResourceSupplier.get();
			registeredClientResource.setId(registeredClient.getId());
			registeredClientResource.setClientId(registeredClient.getClientId());
			registeredClientResource.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
			registeredClientResource.setClientSecret(registeredClient.getClientSecret());
			registeredClientResource.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
			registeredClientResource.setClientName(registeredClient.getClientName());
			registeredClientResource.setClientAuthenticationMethods(clientAuthenticationMethods);
			registeredClientResource.setAuthorizationGrantTypes(authorizationGrantTypes);
			registeredClientResource.setRedirectUris(registeredClient.getRedirectUris());
			registeredClientResource.setScopes(registeredClient.getScopes());
			registeredClientResource.setClientSettings(registeredClient.getClientSettings().getSettings());
			registeredClientResource.setTokenSettings(registeredClient.getTokenSettings().getSettings());

			return registeredClientResource;
		};
	}

	/**
	 * Returns a {@link Function} for mapping a {@link RegisteredClientResource} to a {@link RegisteredClient}.
	 *
	 * @return A {@link Function} for mapping a {@link RegisteredClientResource} to a {@link RegisteredClient}.
	 */
	public static Function<RegisteredClientResource, RegisteredClient> registeredClientMapper() {
		return registeredClientMapper(defaultConsumer());
	}

	/**
	 * Returns a {@link Function} for mapping a {@link RegisteredClientResource} to a {@link RegisteredClient}.
	 *
	 * @param registeredClientBuilderConsumer A {@link BiConsumer} used to access the builder for customizing the mapping
	 * @return A {@link Function} for mapping a {@link RegisteredClientResource} to a {@link RegisteredClient}.
	 */
	public static Function<RegisteredClientResource, RegisteredClient> registeredClientMapper(
			BiConsumer<RegisteredClientResource, RegisteredClient.Builder> registeredClientBuilderConsumer) {
		return (registeredClientResource) -> {
			RegisteredClient.Builder builder = RegisteredClient.withId(registeredClientResource.getId())
					.clientId(registeredClientResource.getClientId())
					.clientIdIssuedAt(registeredClientResource.getClientIdIssuedAt())
					.clientSecret(registeredClientResource.getClientSecret())
					.clientSecretExpiresAt(registeredClientResource.getClientSecretExpiresAt())
					.clientName(registeredClientResource.getClientName())
					.clientAuthenticationMethods(authenticationMethods ->
							registeredClientResource.getClientAuthenticationMethods().forEach(authenticationMethod ->
									authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
					.authorizationGrantTypes((grantTypes) ->
							registeredClientResource.getAuthorizationGrantTypes().forEach(grantType ->
									grantTypes.add(resolveAuthorizationGrantType(grantType))))
					.redirectUris((uris) -> uris.addAll(registeredClientResource.getRedirectUris()))
					.scopes((scopes) -> scopes.addAll(registeredClientResource.getScopes()))
					.clientSettings(ClientSettings.withSettings(registeredClientResource.getClientSettings()).build())
					.tokenSettings(TokenSettings.withSettings(registeredClientResource.getTokenSettings()).build());
			registeredClientBuilderConsumer.accept(registeredClientResource, builder);

			return builder.build();
		};
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2Authorization} to a {@link OAuth2AuthorizationResource}.
	 *
	 * @return A {@link Function} for mapping a {@link OAuth2Authorization} to a {@link OAuth2AuthorizationResource}.
	 */
	public static Function<OAuth2Authorization, OAuth2AuthorizationResource> authorizationResourceMapper() {
		return authorizationResourceMapper(OAuth2AuthorizationResource::new);
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2Authorization} to a {@link OAuth2AuthorizationResource}.
	 *
	 * @param authorizationResourceSupplier A {@link Supplier} providing a custom object
	 * @return A {@link Function} for mapping a {@link OAuth2Authorization} to a {@link OAuth2AuthorizationResource}.
	 */
	public static Function<OAuth2Authorization, OAuth2AuthorizationResource> authorizationResourceMapper(
			Supplier<OAuth2AuthorizationResource> authorizationResourceSupplier) {
		return (authorization) -> {
			OAuth2AuthorizationResource authorizationResource = authorizationResourceSupplier.get();
			authorizationResource.setId(authorization.getId());
			authorizationResource.setRegisteredClientId(authorization.getRegisteredClientId());
			authorizationResource.setPrincipalName(authorization.getPrincipalName());
			authorizationResource.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
			authorizationResource.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));
			authorizationResource.setAttributes(authorization.getAttributes());

			Map<String, OAuth2AuthorizationResource.OAuth2TokenResource> tokenResources = new HashMap<>();
			TOKEN_TYPES.forEach((key, tokenType) -> {
				OAuth2Authorization.Token<?> authorizationToken = authorization.getToken(tokenType);
				if (authorizationToken != null) {
					OAuth2Token token = authorizationToken.getToken();
					if (token instanceof OAuth2AccessToken) {
						// Set scopes as top-level field
						OAuth2AccessToken accessToken = (OAuth2AccessToken) token;
						authorizationResource.setScopes(accessToken.getScopes());
					}

					OAuth2AuthorizationResource.OAuth2TokenResource tokenResource =
							new OAuth2AuthorizationResource.OAuth2TokenResource();
					tokenResource.setTokenValue(token.getTokenValue());
					tokenResource.setIssuedAt(token.getIssuedAt());
					tokenResource.setExpiresAt(token.getExpiresAt());
					tokenResource.setMetadata(authorizationToken.getMetadata());
					tokenResources.put(key, tokenResource);
				}
			});
			authorizationResource.setTokens(Collections.unmodifiableMap(tokenResources));

			return authorizationResource;
		};
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2AuthorizationResource} to a {@link OAuth2Authorization}.
	 *
	 * @return A {@link Function} for mapping a {@link OAuth2AuthorizationResource} to a {@link OAuth2Authorization}.
	 */
	public static Function<OAuth2AuthorizationResource, OAuth2Authorization> authorizationMapper() {
		return authorizationMapper(defaultConsumer());
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2AuthorizationResource} to a {@link OAuth2Authorization}.
	 *
	 * @param authorizationBuilderConsumer A {@link BiConsumer} used to access the builder for customizing the mapping
	 * @return A {@link Function} for mapping a {@link OAuth2AuthorizationResource} to a {@link OAuth2Authorization}.
	 */
	public static Function<OAuth2AuthorizationResource, OAuth2Authorization> authorizationMapper(
			BiConsumer<OAuth2AuthorizationResource, OAuth2Authorization.Builder> authorizationBuilderConsumer) {
		return (authorizationResource) -> {
			OAuth2Authorization.Builder builder = new OAuth2Authorization.Builder(
					authorizationResource.getRegisteredClientId())
					.id(authorizationResource.getId())
					.principalName(authorizationResource.getPrincipalName())
					.authorizationGrantType(resolveAuthorizationGrantType(
							authorizationResource.getAuthorizationGrantType()))
					.attributes((attributes) -> attributes.putAll(authorizationResource.getAttributes()));
			if (authorizationResource.getState() != null) {
				builder.attribute(OAuth2ParameterNames.STATE, authorizationResource.getState());
			}
			TOKEN_TYPES.forEach((key, tokenType) -> {
				OAuth2AuthorizationResource.OAuth2TokenResource tokenResource = authorizationResource.getTokens()
						.get(key);
				if (tokenResource != null) {
					OAuth2Token token = createOAuth2Token(tokenType, tokenResource, authorizationResource);
					builder.token(token, metadata -> metadata.putAll(tokenResource.getMetadata()));
				}
			});
			authorizationBuilderConsumer.accept(authorizationResource, builder);

			return builder.build();
		};
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2AuthorizationConsent} to a
	 * {@link OAuth2AuthorizationConsentResource}.
	 *
	 * @return A {@link Function} for mapping a {@link OAuth2AuthorizationConsent} to a
	 * {@link OAuth2AuthorizationConsentResource}.
	 */
	public static Function<OAuth2AuthorizationConsent, OAuth2AuthorizationConsentResource> authorizationConsentResourceMapper() {
		return authorizationConsentResourceMapper(OAuth2AuthorizationConsentResource::new);
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2AuthorizationConsent} to a
	 * {@link OAuth2AuthorizationConsentResource}.
	 *
	 * @param authorizationConsentResourceSupplier A {@link Supplier} providing a custom object
	 * @return A {@link Function} for mapping a {@link OAuth2AuthorizationConsent} to a
	 * {@link OAuth2AuthorizationConsentResource}.
	 */
	public static Function<OAuth2AuthorizationConsent, OAuth2AuthorizationConsentResource> authorizationConsentResourceMapper(
			Supplier<OAuth2AuthorizationConsentResource> authorizationConsentResourceSupplier) {
		return (authorizationConsent) -> {
			OAuth2AuthorizationConsentResource authorizationConsentResource =
					authorizationConsentResourceSupplier.get();
			authorizationConsentResource.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
			authorizationConsentResource.setPrincipalName(authorizationConsent.getPrincipalName());

			Set<String> authorities = new HashSet<>();
			authorizationConsent.getAuthorities().forEach(authority -> authorities.add(authority.getAuthority()));
			authorizationConsentResource.setAuthorities(authorities);

			return authorizationConsentResource;
		};
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2AuthorizationConsentResource} to a
	 * {@link OAuth2AuthorizationConsent}.
	 *
	 * @return A {@link Function} for mapping a {@link OAuth2AuthorizationConsentResource} to a
	 * {@link OAuth2AuthorizationConsent}.
	 */
	public static Function<OAuth2AuthorizationConsentResource, OAuth2AuthorizationConsent> authorizationConsentMapper() {
		return authorizationConsentMapper(defaultConsumer());
	}

	/**
	 * Returns a {@link Function} for mapping a {@link OAuth2AuthorizationConsentResource} to a
	 * {@link OAuth2AuthorizationConsent}.
	 *
	 * @param authorizationConsentBuilderConsumer A {@link BiConsumer} used to access the builder for customizing the mapping
	 * @return A {@link Function} for mapping a {@link OAuth2AuthorizationConsentResource} to a
	 * {@link OAuth2AuthorizationConsent}.
	 */
	public static Function<OAuth2AuthorizationConsentResource, OAuth2AuthorizationConsent> authorizationConsentMapper(
			BiConsumer<OAuth2AuthorizationConsentResource, OAuth2AuthorizationConsent.Builder> authorizationConsentBuilderConsumer) {
		return (authorizationConsentResource) -> {
			OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
					authorizationConsentResource.getRegisteredClientId(),
					authorizationConsentResource.getPrincipalName());
			authorizationConsentResource.getAuthorities().forEach(authority ->
					builder.authority(new SimpleGrantedAuthority(authority)));
			authorizationConsentBuilderConsumer.accept(authorizationConsentResource, builder);

			return builder.build();
		};
	}

	// @formatter:off
	private static OAuth2Token createOAuth2Token(
			Class<? extends OAuth2Token> tokenType,
			OAuth2AuthorizationResource.OAuth2TokenResource tokenResource,
			OAuth2AuthorizationResource authorizationResource) {
		if (tokenType == OAuth2AuthorizationCode.class) {
			return new OAuth2AuthorizationCode(
					tokenResource.getTokenValue(),
					tokenResource.getIssuedAt(),
					tokenResource.getExpiresAt());
		} else if (tokenType == OAuth2AccessToken.class) {
			return new OAuth2AccessToken(
					OAuth2AccessToken.TokenType.BEARER,
					tokenResource.getTokenValue(),
					tokenResource.getIssuedAt(),
					tokenResource.getExpiresAt(),
					authorizationResource.getScopes());
		} else if (tokenType == OAuth2RefreshToken.class) {
			return new OAuth2RefreshToken(
					tokenResource.getTokenValue(),
					tokenResource.getIssuedAt(),
					tokenResource.getExpiresAt());
		} else if (tokenType == OidcIdToken.class) {
			@SuppressWarnings("unchecked")
			Map<String, Object> claims = (Map<String, Object>) tokenResource.getMetadata()
					.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
			return new OidcIdToken(
					tokenResource.getTokenValue(),
					tokenResource.getIssuedAt(),
					tokenResource.getExpiresAt(),
					claims);
		}
		return null;
	}
	// @formatter:on

	private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_JWT;
		} else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.PRIVATE_KEY_JWT;
		} else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.NONE;
		}
		return new ClientAuthenticationMethod(clientAuthenticationMethod);      // Custom client authentication method
	}

	private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.AUTHORIZATION_CODE;
		} else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.CLIENT_CREDENTIALS;
		} else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.REFRESH_TOKEN;
		} else if (AuthorizationGrantType.JWT_BEARER.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.JWT_BEARER;
		}
		return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
	}

	private static <T, B> BiConsumer<T, B> defaultConsumer() {
		return (resource, builder) -> {
		};
	}
}
