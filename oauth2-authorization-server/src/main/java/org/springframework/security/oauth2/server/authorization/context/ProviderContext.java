/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.context;

import java.util.function.Supplier;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.util.Assert;

/**
 * A context that holds information of the Provider.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerSettings
 * @see ProviderContextHolder
 */
public final class ProviderContext {
	private final AuthorizationServerSettings authorizationServerSettings;
	private final Supplier<String> issuerSupplier;

	/**
	 * Constructs a {@code ProviderContext} using the provided parameters.
	 *
	 * @param authorizationServerSettings the authorization server settings
	 * @param issuerSupplier a {@code Supplier} for the {@code URL} of the Provider's issuer identifier
	 */
	public ProviderContext(AuthorizationServerSettings authorizationServerSettings, @Nullable Supplier<String> issuerSupplier) {
		Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
		this.authorizationServerSettings = authorizationServerSettings;
		this.issuerSupplier = issuerSupplier;
	}

	/**
	 * Returns the {@link AuthorizationServerSettings}.
	 *
	 * @return the {@link AuthorizationServerSettings}
	 */
	public AuthorizationServerSettings getAuthorizationServerSettings() {
		return this.authorizationServerSettings;
	}

	/**
	 * Returns the {@code URL} of the Provider's issuer identifier.
	 * The issuer identifier is resolved from the constructor parameter {@code Supplier<String>}
	 * or if not provided then defaults to {@link AuthorizationServerSettings#getIssuer()}.
	 *
	 * @return the {@code URL} of the Provider's issuer identifier
	 */
	public String getIssuer() {
		return this.issuerSupplier != null ?
				this.issuerSupplier.get() :
				getAuthorizationServerSettings().getIssuer();
	}

}
