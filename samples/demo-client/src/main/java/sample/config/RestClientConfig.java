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

import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import sample.authorization.DeviceCodeOAuth2AuthorizedClientProvider;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultOAuth2TokenRequestParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestClient;

/**
 * @author Joe Grandja
 * @since 1.3
 */
@Configuration(proxyBeanMethods = false)
public class RestClientConfig {

	@Bean("default-client-rest-client")
	public RestClient defaultClientRestClient(
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			OAuth2AuthorizedClientManager authorizedClientManager,
			@Qualifier("default-client-http-request-factory") Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		OAuth2ClientHttpRequestInterceptor requestInterceptor =
				new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
		OAuth2AuthorizationFailureHandler authorizationFailureHandler =
				OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClientRepository);
		requestInterceptor.setAuthorizationFailureHandler(authorizationFailureHandler);
		// @formatter:off
		return RestClient.builder()
				.requestFactory(clientHttpRequestFactory.get())
				.requestInterceptor(requestInterceptor)
				.build();
		// @formatter:on
	}

	@Bean("self-signed-demo-client-rest-client")
	public RestClient selfSignedDemoClientRestClient(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			@Qualifier("self-signed-demo-client-http-request-factory") Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		RestClient restClient = accessTokenRestClient(clientHttpRequestFactory);

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

		OAuth2ClientHttpRequestInterceptor requestInterceptor =
				new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
		OAuth2AuthorizationFailureHandler authorizationFailureHandler =
				OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClientRepository);
		requestInterceptor.setAuthorizationFailureHandler(authorizationFailureHandler);

		// @formatter:off
		return RestClient.builder()
				.requestFactory(clientHttpRequestFactory.get())
				.requestInterceptor(requestInterceptor)
				.build();
		// @formatter:on
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			@Qualifier("default-client-http-request-factory") Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		RestClient restClient = accessTokenRestClient(clientHttpRequestFactory);

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

	@Bean("default-client-http-request-factory")
	Supplier<ClientHttpRequestFactory> defaultClientHttpRequestFactory(SslBundles sslBundles) {
		return () -> {
			SslBundle sslBundle = sslBundles.getBundle("demo-client");
			final SSLContext sslContext = sslBundle.createSslContext();
			final SSLConnectionSocketFactory sslConnectionSocketFactory =
					new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
			final Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.register("https", sslConnectionSocketFactory)
					.build();
			final BasicHttpClientConnectionManager connectionManager =
					new BasicHttpClientConnectionManager(socketFactoryRegistry);
			final CloseableHttpClient httpClient = HttpClients.custom()
					.setConnectionManager(connectionManager)
					.build();
			return new HttpComponentsClientHttpRequestFactory(httpClient);
		};
	}

	@Bean("self-signed-demo-client-http-request-factory")
	Supplier<ClientHttpRequestFactory> selfSignedDemoClientHttpRequestFactory(SslBundles sslBundles) {
		return () -> {
			SslBundle sslBundle = sslBundles.getBundle("self-signed-demo-client");
			final SSLContext sslContext = sslBundle.createSslContext();
			final SSLConnectionSocketFactory sslConnectionSocketFactory =
					new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
			final Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("https", sslConnectionSocketFactory)
					.build();
			final BasicHttpClientConnectionManager connectionManager =
					new BasicHttpClientConnectionManager(socketFactoryRegistry);
			final CloseableHttpClient httpClient = HttpClients.custom()
					.setConnectionManager(connectionManager)
					.build();
			return new HttpComponentsClientHttpRequestFactory(httpClient);
		};
	}

	private static RestClient accessTokenRestClient(Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {
		// @formatter:off
		return RestClient.builder()
				.requestFactory(clientHttpRequestFactory.get())
				.messageConverters((messageConverters) -> {
					messageConverters.clear();
					messageConverters.add(new FormHttpMessageConverter());
					messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
				})
				.defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
				.build();
		// @formatter:on

	}

	private static OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> createClientCredentialsTokenResponseClient(
			RestClient restClient) {
		RestClientClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient =
				new RestClientClientCredentialsTokenResponseClient();
		clientCredentialsTokenResponseClient.setParametersConverter(new DefaultOAuth2TokenRequestParametersConverter<>());
		clientCredentialsTokenResponseClient.setRestClient(restClient);

		return clientCredentialsTokenResponseClient;
	}

}
