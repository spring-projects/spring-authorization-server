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
package org.springframework.security.oauth2.server.authorization.config;


import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/**
 * A facility for OpenID Connect Provider Configuration settings.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see Settings
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect Discovery 1.0</a>
 */
public class ProviderSettings extends Settings {
	private static final String PROVIDER_SETTING_BASE = "setting.provider.";
	public static final String ISSUER = PROVIDER_SETTING_BASE.concat("issuer");
	public static final String AUTHORIZATION_ENDPOINT = PROVIDER_SETTING_BASE.concat("authorization-endpoint");
	public static final String TOKEN_ENDPOINT = PROVIDER_SETTING_BASE.concat("token-endpoint");
	public static final String JWK_SET_ENDPOINT = PROVIDER_SETTING_BASE.concat("jwk-set-endpoint");
	public static final String TOKEN_REVOCATION_ENDPOINT = PROVIDER_SETTING_BASE.concat("token-revocation-endpoint");

	/**
	 * Constructs a {@code ProviderSettings}.
	 */
	public ProviderSettings() {
		super(defaultSettings());
	}

	/**
	 * Returns the URL for the OpenID Issuer.
	 *
	 * @return the URL for the OpenID Issuer
	 */
	public String issuer() {
		return setting(ISSUER);
	}

	/**
	 * Sets the URL the Provider uses as its Issuer Identity.
	 *
	 * @param issuer the URL the Provider uses as its Issuer Identity.
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings issuer(String issuer) {
		Assert.notNull(issuer, "issuer cannot be null");
		return setting(ISSUER, issuer);
	}

	/**
	 * Returns the provider's OAuth 2.0 Authorization endpoint. The default is {@code /oauth2/authorize}.
	 *
	 * @return the Authorization endpoint
	 */
	public String authorizationEndpoint() {
		return setting(AUTHORIZATION_ENDPOINT);
	}

	/**
	 * Sets the provider's OAuth 2.0 Authorization endpoint.
	 *
	 * @param authorizationEndpoint the Authorization endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings authorizationEndpoint(String authorizationEndpoint) {
		Assert.hasText(authorizationEndpoint, "authorizationEndpoint cannot be empty");
		return setting(AUTHORIZATION_ENDPOINT, authorizationEndpoint);
	}

	/**
	 * Returns the provider's OAuth 2.0 Token endpoint. The default is {@code /oauth2/token}.
	 *
	 * @return the Token endpoint
	 */
	public String tokenEndpoint() {
		return setting(TOKEN_ENDPOINT);
	}

	/**
	 * Sets the provider's OAuth 2.0 Token endpoint.
	 *
	 * @param tokenEndpoint the Token endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings tokenEndpoint(String tokenEndpoint) {
		Assert.hasText(tokenEndpoint, "tokenEndpoint cannot be empty");
		return setting(TOKEN_ENDPOINT, tokenEndpoint);
	}

	/**
	 * Returns the provider's JWK Set endpoint. The default is {@code /oauth2/jwks}.
	 *
	 * @return the JWK Set endpoint
	 */
	public String jwkSetEndpoint() {
		return setting(JWK_SET_ENDPOINT);
	}

	/**
	 * Sets the provider's OAuth 2.0 JWK Set endpoint.
	 *
	 * @param jwkSetEndpoint the JWK Set endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings jwkSetEndpoint(String jwkSetEndpoint) {
		Assert.hasText(jwkSetEndpoint, "jwkSetEndpoint cannot be empty");
		return setting(JWK_SET_ENDPOINT, jwkSetEndpoint);
	}

	/**
	 * Returns the provider's Token Revocation endpoint. The default is {@code /oauth2/revoke}.
	 *
	 * @return the Token Revocation endpoint
	 */
	public String tokenRevocationEndpoint() {
		return setting(TOKEN_REVOCATION_ENDPOINT);
	}

	/**
	 * Sets the provider's OAuth 2.0 Token Revocation endpoint.
	 *
	 * @param tokenRevocationEndpoint the Token Revocation endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings tokenRevocationEndpoint(String tokenRevocationEndpoint) {
		Assert.hasText(tokenRevocationEndpoint, "tokenRevocationEndpoint cannot be empty");
		return setting(TOKEN_REVOCATION_ENDPOINT, tokenRevocationEndpoint);
	}

	protected static Map<String, Object> defaultSettings() {
		Map<String, Object> settings = new HashMap<>();
		settings.put(AUTHORIZATION_ENDPOINT, "/oauth2/authorize");
		settings.put(TOKEN_ENDPOINT, "/oauth2/token");
		settings.put(JWK_SET_ENDPOINT, "/oauth2/jwks");
		settings.put(TOKEN_REVOCATION_ENDPOINT, "/oauth2/revoke");
		return settings;
	}
}
