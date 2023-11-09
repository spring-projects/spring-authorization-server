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
package sample.registration;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.CollectionUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

public class CustomMetadataConfig {
	public static Consumer<List<AuthenticationProvider>> registeredClientConverters() {
		List<String> customClientMetadata = List.of("logo_uri", "contacts"); // <1>

		return authenticationProviders -> // <2>
		{
			CustomRegisteredClientConverter registeredClientConverter = new CustomRegisteredClientConverter(customClientMetadata);
			CustomClientRegistrationConverter clientRegistrationConverter = new CustomClientRegistrationConverter(customClientMetadata);

			authenticationProviders.forEach(authenticationProvider -> {
				if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) { // <3>
					provider.setRegisteredClientConverter(registeredClientConverter); // <4>
					provider.setClientRegistrationConverter(clientRegistrationConverter); // <5>
				}

				if (authenticationProvider instanceof OidcClientConfigurationAuthenticationProvider provider) {
					provider.setClientRegistrationConverter(clientRegistrationConverter); // <6>
				}
			});
		};
	}

	static class CustomRegisteredClientConverter implements Converter<OidcClientRegistration, RegisteredClient> { // <7>
		private final List<String> customMetadata;

		private final OidcClientRegistrationRegisteredClientConverter delegate;

		CustomRegisteredClientConverter(List<String> customMetadata) {
			this.customMetadata = customMetadata;
			this.delegate = new OidcClientRegistrationRegisteredClientConverter();
		}

		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			RegisteredClient convertedClient = delegate.convert(clientRegistration);
			ClientSettings.Builder clientSettingsBuilder = ClientSettings
					.withSettings(convertedClient.getClientSettings().getSettings());

			if (!CollectionUtils.isEmpty(this.customMetadata)) {
				clientRegistration.getClaims().forEach((claim, value) -> {
					if (this.customMetadata.contains(claim)) {
						clientSettingsBuilder.setting(claim, value);
					}
				});
			}

			return RegisteredClient.from(convertedClient).clientSettings(clientSettingsBuilder.build()).build();
		}
	}

	static class CustomClientRegistrationConverter implements Converter<RegisteredClient, OidcClientRegistration> { // <8>
		private final List<String> customMetadata;

		private final RegisteredClientOidcClientRegistrationConverter delegate;

		CustomClientRegistrationConverter(List<String> customMetadata) {
			this.customMetadata = customMetadata;
			this.delegate = new RegisteredClientOidcClientRegistrationConverter();
		}

		public OidcClientRegistration convert(RegisteredClient registeredClient) {
			var clientRegistration = delegate.convert(registeredClient);
			Map<String, Object> claims = new HashMap<>(clientRegistration.getClaims());
			if (!CollectionUtils.isEmpty(customMetadata)) {
				ClientSettings clientSettings = registeredClient.getClientSettings();

				claims.putAll(customMetadata.stream()
						.filter(metadatum -> clientSettings.getSetting(metadatum) != null)
						.collect(Collectors.toMap(Function.identity(), clientSettings::getSetting)));
			}
			return OidcClientRegistration.withClaims(claims).build();
		}
	}

}
