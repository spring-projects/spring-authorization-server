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

import org.apache.catalina.connector.Connector;

import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Joe Grandja
 * @since 1.3
 */
@Configuration(proxyBeanMethods = false)
public class TomcatServerConfig {

	@Bean
	public WebServerFactoryCustomizer<TomcatServletWebServerFactory> connectorCustomizer() {
		return (tomcat) -> tomcat.addAdditionalTomcatConnectors(createHttpConnector());
	}

	private Connector createHttpConnector() {
		Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
		connector.setScheme("http");
		connector.setPort(8090);
		connector.setSecure(false);
		connector.setRedirectPort(8443);
		return connector;
	}

}
