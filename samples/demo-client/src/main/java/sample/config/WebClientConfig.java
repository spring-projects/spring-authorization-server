/*
 * Copyright 2020-2025 the original author or authors.
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
package sample.config;

import java.util.function.Supplier;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.SslProvider;
import sample.authorization.DeviceCodeOAuth2AuthorizedClientProvider;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 0.0.1
 */
@Configuration(proxyBeanMethods = false)
public class WebClientConfig {

	@Bean("default-client-web-client")
	public WebClient defaultClientWebClient(
			OAuth2AuthorizedClientManager authorizedClientManager,
			SslBundles sslBundles) throws Exception {

		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		// @formatter:off
		return WebClient.builder()
				.clientConnector(createClientConnector(sslBundles.getBundle("demo-client")))
				.apply(oauth2Client.oauth2Configuration())
				.build();
		// @formatter:on
	}

	@Bean("self-signed-demo-client-web-client")
	public WebClient selfSignedDemoClientWebClient(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			@Qualifier("self-signed-demo-client-http-request-factory") Supplier<ClientHttpRequestFactory> clientHttpRequestFactory,
			SslBundles sslBundles) throws Exception {

		// @formatter:off
		RestClient restClient = RestClient.builder()
				.requestFactory(clientHttpRequestFactory.get())
				.messageConverters((messageConverters) -> {
					messageConverters.clear();
					messageConverters.add(new FormHttpMessageConverter());
					messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
				})
				.defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
				.build();
		// @formatter:on

		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.clientCredentials(clientCredentials ->
								clientCredentials.accessTokenResponseClient(
										createClientCredentialsTokenResponseClient(restClient)))
						.build();
		// @formatter:on

		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		// @formatter:off
		return WebClient.builder()
				.clientConnector(createClientConnector(sslBundles.getBundle("self-signed-demo-client")))
				.apply(oauth2Client.oauth2Configuration())
				.build();
		// @formatter:on
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			@Qualifier("default-client-http-request-factory") Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		// @formatter:off
		RestClient restClient = RestClient.builder()
				.requestFactory(clientHttpRequestFactory.get())
				.messageConverters((messageConverters) -> {
					messageConverters.clear();
					messageConverters.add(new FormHttpMessageConverter());
					messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
				})
				.defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
				.build();
		// @formatter:on

		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
						.clientCredentials(clientCredentials ->
								clientCredentials.accessTokenResponseClient(
										createClientCredentialsTokenResponseClient(restClient)))
						.provider(new DeviceCodeOAuth2AuthorizedClientProvider())
						.build();
		// @formatter:on

		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		// Set a contextAttributesMapper to obtain device_code from the request
		authorizedClientManager.setContextAttributesMapper(DeviceCodeOAuth2AuthorizedClientProvider
				.deviceCodeContextAttributesMapper());

		return authorizedClientManager;
	}

	private static ClientHttpConnector createClientConnector(SslBundle sslBundle) throws Exception {
		KeyManagerFactory keyManagerFactory = sslBundle.getManagers().getKeyManagerFactory();
		TrustManagerFactory trustManagerFactory = sslBundle.getManagers().getTrustManagerFactory();

		// @formatter:off
		SslContext sslContext = SslContextBuilder.forClient()
				.keyManager(keyManagerFactory)
				.trustManager(trustManagerFactory)
				.build();
		// @formatter:on

		SslProvider sslProvider = SslProvider.builder().sslContext(sslContext).build();
		HttpClient httpClient = HttpClient.create().secure(sslProvider);
		return new ReactorClientHttpConnector(httpClient);
	}

	private static OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> createClientCredentialsTokenResponseClient(
			RestClient restClient) {
		RestClientClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient =
				new RestClientClientCredentialsTokenResponseClient();
		clientCredentialsTokenResponseClient.addParametersConverter(authorizationGrantRequest -> {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			// client_id parameter is required for tls_client_auth method
			parameters.add(OAuth2ParameterNames.CLIENT_ID, authorizationGrantRequest.getClientRegistration().getClientId());
			return parameters;
		});
		clientCredentialsTokenResponseClient.setRestClient(restClient);

		return clientCredentialsTokenResponseClient;
	}

}
