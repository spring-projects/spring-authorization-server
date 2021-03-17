/*
 * Copyright 2020-2021 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

/**
 * A facility for provider configuration settings.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see Settings
 */
public class ProviderSettings extends Settings {
	private static final String PROVIDER_SETTING_BASE = "setting.provider.";
	public static final String ISSUER = PROVIDER_SETTING_BASE.concat("issuer");
	public static final String AUTHORIZATION_ENDPOINT = PROVIDER_SETTING_BASE.concat("authorization-endpoint");
	public static final String TOKEN_ENDPOINT = PROVIDER_SETTING_BASE.concat("token-endpoint");
	public static final String JWK_SET_ENDPOINT = PROVIDER_SETTING_BASE.concat("jwk-set-endpoint");
	public static final String TOKEN_REVOCATION_ENDPOINT = PROVIDER_SETTING_BASE.concat("token-revocation-endpoint");
	public static final String TOKEN_INTROSPECTION_ENDPOINT = PROVIDER_SETTING_BASE.concat("token-introspection-endpoint");

	/**
	 * Constructs a {@code ProviderSettings}.
	 */
	public ProviderSettings() {
		this(defaultSettings());
	}

	/**
	 * Constructs a {@code ProviderSettings} using the provided parameters.
	 *
	 * @param settings the initial settings
	 */
	public ProviderSettings(Map<String, Object> settings) {
		super(settings);
	}

	/**
	 * Returns the URL of the Provider's Issuer Identifier
	 *
	 * @return the URL of the Provider's Issuer Identifier
	 */
	public String issuer() {
		return setting(ISSUER);
	}

	/**
	 * Sets the URL the Provider uses as its Issuer Identifier.
	 *
	 * @param issuer the URL the Provider uses as its Issuer Identifier.
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings issuer(String issuer) {
		return setting(ISSUER, issuer);
	}

	/**
	 * Returns the Provider's OAuth 2.0 Authorization endpoint. The default is {@code /oauth2/authorize}.
	 *
	 * @return the Authorization endpoint
	 */
	public String authorizationEndpoint() {
		return setting(AUTHORIZATION_ENDPOINT);
	}

	/**
	 * Sets the Provider's OAuth 2.0 Authorization endpoint.
	 *
	 * @param authorizationEndpoint the Authorization endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings authorizationEndpoint(String authorizationEndpoint) {
		return setting(AUTHORIZATION_ENDPOINT, authorizationEndpoint);
	}

	/**
	 * Returns the Provider's OAuth 2.0 Token endpoint. The default is {@code /oauth2/token}.
	 *
	 * @return the Token endpoint
	 */
	public String tokenEndpoint() {
		return setting(TOKEN_ENDPOINT);
	}

	/**
	 * Sets the Provider's OAuth 2.0 Token endpoint.
	 *
	 * @param tokenEndpoint the Token endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings tokenEndpoint(String tokenEndpoint) {
		return setting(TOKEN_ENDPOINT, tokenEndpoint);
	}

	/**
	 * Returns the Provider's JWK Set endpoint. The default is {@code /oauth2/jwks}.
	 *
	 * @return the JWK Set endpoint
	 */
	public String jwkSetEndpoint() {
		return setting(JWK_SET_ENDPOINT);
	}

	/**
	 * Sets the Provider's JWK Set endpoint.
	 *
	 * @param jwkSetEndpoint the JWK Set endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings jwkSetEndpoint(String jwkSetEndpoint) {
		return setting(JWK_SET_ENDPOINT, jwkSetEndpoint);
	}

	/**
	 * Returns the Provider's OAuth 2.0 Token Revocation endpoint. The default is {@code /oauth2/revoke}.
	 *
	 * @return the Token Revocation endpoint
	 */
	public String tokenRevocationEndpoint() {
		return setting(TOKEN_REVOCATION_ENDPOINT);
	}

	/**
	 * Sets the Provider's OAuth 2.0 Token Revocation endpoint.
	 *
	 * @param tokenRevocationEndpoint the Token Revocation endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings tokenRevocationEndpoint(String tokenRevocationEndpoint) {
		return setting(TOKEN_REVOCATION_ENDPOINT, tokenRevocationEndpoint);
	}

	/**
	 * Returns the Provider's OAuth 2.0 Token Introspection endpoint. The default is {@code /oauth2/introspect}.
	 *
	 * @return the Token Introspection endpoint
	 */
	public String tokenIntrospectionEndpoint() {
		return setting(TOKEN_INTROSPECTION_ENDPOINT);
	}

	/**
	 * Sets the Provider's OAuth 2.0 Token Introspection endpoint.
	 *
	 * @param tokenIntrospectionEndpoint the Token Introspection endpoint
	 * @return the {@link ProviderSettings} for further configuration
	 */
	public ProviderSettings tokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
		return setting(TOKEN_INTROSPECTION_ENDPOINT, tokenIntrospectionEndpoint);
	}

	protected static Map<String, Object> defaultSettings() {
		Map<String, Object> settings = new HashMap<>();
		settings.put(AUTHORIZATION_ENDPOINT, "/oauth2/authorize");
		settings.put(TOKEN_ENDPOINT, "/oauth2/token");
		settings.put(JWK_SET_ENDPOINT, "/oauth2/jwks");
		settings.put(TOKEN_REVOCATION_ENDPOINT, "/oauth2/revoke");
		settings.put(TOKEN_INTROSPECTION_ENDPOINT, "/oauth2/introspect");
		return settings;
	}
}
