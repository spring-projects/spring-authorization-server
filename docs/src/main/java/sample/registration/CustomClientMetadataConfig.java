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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

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

public class CustomClientMetadataConfig {

	public static Consumer<List<AuthenticationProvider>> configureCustomClientMetadataConverters() {	// <1>
		List<String> customClientMetadata = List.of("logo_uri", "contacts");	// <2>

		return (authenticationProviders) -> {
			CustomRegisteredClientConverter registeredClientConverter =
					new CustomRegisteredClientConverter(customClientMetadata);
			CustomClientRegistrationConverter clientRegistrationConverter =
					new CustomClientRegistrationConverter(customClientMetadata);

			authenticationProviders.forEach((authenticationProvider) -> {
				if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
					provider.setRegisteredClientConverter(registeredClientConverter);	// <3>
					provider.setClientRegistrationConverter(clientRegistrationConverter);	// <4>
				}
				if (authenticationProvider instanceof OidcClientConfigurationAuthenticationProvider provider) {
					provider.setClientRegistrationConverter(clientRegistrationConverter);	// <5>
				}
			});
		};
	}

	private static class CustomRegisteredClientConverter
			implements Converter<OidcClientRegistration, RegisteredClient> {

		private final List<String> customClientMetadata;
		private final OidcClientRegistrationRegisteredClientConverter delegate;

		private CustomRegisteredClientConverter(List<String> customClientMetadata) {
			this.customClientMetadata = customClientMetadata;
			this.delegate = new OidcClientRegistrationRegisteredClientConverter();
		}

		@Override
		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			RegisteredClient registeredClient = this.delegate.convert(clientRegistration);
			ClientSettings.Builder clientSettingsBuilder = ClientSettings.withSettings(
					registeredClient.getClientSettings().getSettings());
			if (!CollectionUtils.isEmpty(this.customClientMetadata)) {
				clientRegistration.getClaims().forEach((claim, value) -> {
					if (this.customClientMetadata.contains(claim)) {
						clientSettingsBuilder.setting(claim, value);
					}
				});
			}

			return RegisteredClient.from(registeredClient)
					.clientSettings(clientSettingsBuilder.build())
					.build();
		}
	}

	private static class CustomClientRegistrationConverter
			implements Converter<RegisteredClient, OidcClientRegistration> {

		private final List<String> customClientMetadata;
		private final RegisteredClientOidcClientRegistrationConverter delegate;

		private CustomClientRegistrationConverter(List<String> customClientMetadata) {
			this.customClientMetadata = customClientMetadata;
			this.delegate = new RegisteredClientOidcClientRegistrationConverter();
		}

		@Override
		public OidcClientRegistration convert(RegisteredClient registeredClient) {
			OidcClientRegistration clientRegistration = this.delegate.convert(registeredClient);
			Map<String, Object> claims = new HashMap<>(clientRegistration.getClaims());
			if (!CollectionUtils.isEmpty(this.customClientMetadata)) {
				ClientSettings clientSettings = registeredClient.getClientSettings();
				claims.putAll(this.customClientMetadata.stream()
						.filter(metadata -> clientSettings.getSetting(metadata) != null)
						.collect(Collectors.toMap(Function.identity(), clientSettings::getSetting)));
			}

			return OidcClientRegistration.withClaims(claims).build();
		}

	}

}
