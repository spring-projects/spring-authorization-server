package com.accesso.security.oauth2.server.authorization.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "accesso.client.externalauth")
@Data
public class ClientExternalAuthenticationConfig {

	// key is clientId
	private Map<String,ClientExternalAuthConfig> config;

	@Data
	static public class ClientExternalAuthConfig {
		private String issuerUri;
		private String tokenUri;
		private String jwkUri;
		private String extClientId;
		private String extClientSecret;
		private Map<String, String> scopeMap;
	}
}
