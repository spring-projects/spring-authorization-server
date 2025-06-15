/*
 * Copyright 2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 */

package org.springframework.security.oauth2.server.authorization;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2DeviceVerificationAuthenticationToken} together with additional
 * information and is used by {@code OAuth2DeviceVerificationAuthenticationProvider} when
 * validating a Device Verification request, as well as determining whether authorization
 * consent is required.
 *
 * @author Your Name
 * @since 1.3.7
 */
public final class OAuth2DeviceVerificationAuthenticationContext implements OAuth2AuthenticationContext {

	private final OAuth2DeviceVerificationAuthenticationToken authentication;

	private final RegisteredClient registeredClient;

	@Nullable
	private final OAuth2Authorization authorization;

	@Nullable
	private final OAuth2AuthorizationConsent authorizationConsent;

	private final Map<Object, Object> context;

	@SuppressWarnings("unchecked")
	@Override
	public <T extends Authentication> T getAuthentication() {
		return (T) this.authentication;
	}

	@Override
	@Nullable
	public <V> V get(Object key) {
		return (V) this.context.get(key);
	}

	@Override
	public boolean hasKey(Object key) {
		return this.context.containsKey(key);
	}

	public RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}

	@Nullable
	public OAuth2Authorization getAuthorization() {
		return this.authorization;
	}

	@Nullable
	public OAuth2AuthorizationConsent getAuthorizationConsent() {
		return this.authorizationConsent;
	}

	/* ======== Builder plumbing ======== */

	private OAuth2DeviceVerificationAuthenticationContext(Builder builder) {
		this.authentication = builder.authentication;
		this.registeredClient = builder.registeredClient;
		this.authorization = builder.authorization;
		this.authorizationConsent = builder.authorizationConsent;
		this.context = Collections.unmodifiableMap(new LinkedHashMap<>(builder.getContext()));
	}

	/**
	 * Returns a new {@link Builder} pre-initialised with the supplied authentication.
	 * @param authentication the {@link OAuth2DeviceVerificationAuthenticationToken}
	 * @return the {@link Builder} for further customisation
	 */
	public static Builder with(OAuth2DeviceVerificationAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2DeviceVerificationAuthenticationContext}.
	 */
	public static final class Builder extends
			OAuth2AuthenticationContext.AbstractBuilder<OAuth2DeviceVerificationAuthenticationContext, Builder> {

		private final OAuth2DeviceVerificationAuthenticationToken authentication;

		private RegisteredClient registeredClient;

		private OAuth2Authorization authorization;

		private OAuth2AuthorizationConsent authorizationConsent;

		private Builder(OAuth2DeviceVerificationAuthenticationToken authentication) {
			super(authentication);
			Assert.notNull(authentication, "authentication cannot be null");
			this.authentication = authentication;
		}

		public Builder registeredClient(RegisteredClient registeredClient) {
			this.registeredClient = registeredClient;
			return this;
		}

		public Builder authorization(@Nullable OAuth2Authorization authorization) {
			this.authorization = authorization;
			return this;
		}

		public Builder authorizationConsent(@Nullable OAuth2AuthorizationConsent authorizationConsent) {
			this.authorizationConsent = authorizationConsent;
			return this;
		}

		@Override
		public OAuth2DeviceVerificationAuthenticationContext build() {
			Assert.notNull(this.registeredClient, "registeredClient cannot be null");
			return new OAuth2DeviceVerificationAuthenticationContext(this);
		}

		@Override
		protected Builder getThis() {
			return this;
		}

	}

}
