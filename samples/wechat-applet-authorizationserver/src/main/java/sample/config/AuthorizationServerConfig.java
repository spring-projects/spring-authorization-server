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
package sample.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2TokenEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2WeChatAuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import sample.jose.Jwks;

import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

/**
 * @author Joe Grandja
 * @author xuxiaowei
 * @since 0.0.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	/**
	 * 微信小程序服务类
	 */
	@Bean
	public WeChatAppletService weChatAppletService() {
		InMemoryWeChatAppletService weChatAppletService = new InMemoryWeChatAppletService();
		String appid = "微信小程序ID，如：wxcf4f3a217a******";
		String secret = "微信小程序秘钥";
		weChatAppletService.setWeChatAppletList(
				Collections.singletonList(new InMemoryWeChatAppletService.WeChatApplet(appid, secret)));
		return weChatAppletService;
	}

	/**
	 * @see <a href=
	 * "https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html">协议端点的</a>
	 * Spring Security 过滤器链。
	 * @see OAuth2AuthorizationServerConfiguration#applyDefaultSecurity(HttpSecurity) 默认
	 * OAuth 2.1 授权配置
	 * @see OAuth2AuthorizationEndpointFilter 默认 OAuth 2.1 授权页面
	 * @see OAuth2TokenEndpointFilter#setAuthenticationConverter(AuthenticationConverter)
	 * @see OAuth2TokenEndpointConfigurer#accessTokenRequestConverter(AuthenticationConverter)
	 * @see AnonymousAuthenticationProvider
	 * @see JwtClientAssertionAuthenticationProvider
	 * @see ClientSecretAuthenticationProvider
	 * @see PublicClientAuthenticationProvider
	 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
	 * @see OAuth2AuthorizationCodeAuthenticationProvider
	 * @see OAuth2RefreshTokenAuthenticationProvider
	 * @see OAuth2ClientCredentialsAuthenticationProvider
	 * @see OAuth2TokenIntrospectionAuthenticationProvider
	 * @see OAuth2TokenRevocationAuthenticationProvider
	 * @see OidcUserInfoAuthenticationProvider
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		// @formatter:off
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.requestMatcher(endpointsMatcher).authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated()).csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher)).apply(authorizationServerConfigurer);
        // @formatter:on

		// 自定义客户授权
		authorizationServerConfigurer.tokenEndpoint(tokenEndpointCustomizer -> tokenEndpointCustomizer
				.accessTokenRequestConverter(new DelegatingAuthenticationConverter(Arrays.asList(
						// 新增：微信 OAuth2 用于验证授权授予的 {@link OAuth2WeChatAuthenticationToken}
						new OAuth2WeChatAppletAuthenticationConverter(),
						// 默认值：OAuth2 授权码认证转换器
						new OAuth2AuthorizationCodeAuthenticationConverter(),
						// 默认值：OAuth2 刷新令牌认证转换器
						new OAuth2RefreshTokenAuthenticationConverter(),
						// 默认值：OAuth2 客户端凭据身份验证转换器
						new OAuth2ClientCredentialsAuthenticationConverter()))));

		OAuth2WeChatAuthorizationServerConfiguration.applyDefaultSecurity(http);

		// @formatter:off
        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        // @formatter:on
		return http.build();
	}

	// @formatter:off
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client").clientSecret("{noop}secret").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).authorizationGrantType(new AuthorizationGrantType("wechat_applet")).scope(OidcScopes.OPENID).scope("message.read").scope("message.write").clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();

        // Save registered client in db as if in-memory
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        registeredClientRepository.save(registeredClient);

        return registeredClientRepository;
    }
    // @formatter:on

	@Bean
	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer("http://localhost:9080").build();
	}

	@Bean
	public EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
        return new EmbeddedDatabaseBuilder().generateUniqueName(true).setType(EmbeddedDatabaseType.H2).setScriptEncoding("UTF-8").addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql").addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql").addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql").build();
        // @formatter:on
	}

}
