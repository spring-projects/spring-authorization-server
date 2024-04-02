/*
 * Copyright 2020-2024 the original author or authors.
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

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

/**
 * @author Joe Grandja
 * @since 1.3
 */
@Configuration(proxyBeanMethods = false)
public class RestTemplateConfig {

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

}
