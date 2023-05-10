/*
 * Copyright 2020-2023 the original author or authors.
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
package sample.federation;

// tag::imports[]

import java.util.function.Consumer;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
// end::imports[]

/**
 * A configurer for setting up Federated Identity Management.
 *
 * @author Steve Riesenberg
 * @since 1.1
 */
// tag::class[]
public final class FederatedIdentityConfigurer extends AbstractHttpConfigurer<FederatedIdentityConfigurer, HttpSecurity> {

	private Consumer<OAuth2User> oauth2UserHandler;

	private Consumer<OidcUser> oidcUserHandler;

	/**
	 * @param oauth2UserHandler The {@link Consumer} for performing JIT account provisioning
	 * with an OAuth 2.0 IDP
	 * @return This configurer for additional configuration
	 */
	public FederatedIdentityConfigurer oauth2UserHandler(Consumer<OAuth2User> oauth2UserHandler) {
		Assert.notNull(oauth2UserHandler, "oauth2UserHandler cannot be null");
		this.oauth2UserHandler = oauth2UserHandler;
		return this;
	}

	/**
	 * @param oidcUserHandler The {@link Consumer} for performing JIT account provisioning
	 * with an OpenID Connect 1.0 IDP
	 * @return This configurer for additional configuration
	 */
	public FederatedIdentityConfigurer oidcUserHandler(Consumer<OidcUser> oidcUserHandler) {
		Assert.notNull(oidcUserHandler, "oidcUserHandler cannot be null");
		this.oidcUserHandler = oidcUserHandler;
		return this;
	}

	// @formatter:off
	@Override
	public void init(HttpSecurity http) throws Exception {
		FederatedIdentityAuthenticationSuccessHandler authenticationSuccessHandler =
			new FederatedIdentityAuthenticationSuccessHandler();
		if (this.oauth2UserHandler != null) {
			authenticationSuccessHandler.setOAuth2UserHandler(this.oauth2UserHandler);
		}
		if (this.oidcUserHandler != null) {
			authenticationSuccessHandler.setOidcUserHandler(this.oidcUserHandler);
		}

		http
			.oauth2Login(oauth2Login ->
					oauth2Login.successHandler(authenticationSuccessHandler)
			);
	}
	// @formatter:on

}
// end::class[]
