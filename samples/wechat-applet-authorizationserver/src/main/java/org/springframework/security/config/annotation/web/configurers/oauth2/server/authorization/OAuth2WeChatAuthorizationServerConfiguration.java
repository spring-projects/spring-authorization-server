package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2WeChatAppletAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryWeChatAppletService;
import org.springframework.security.oauth2.server.authorization.client.WeChatAppletService;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * 微信 OAuth2 授权服务配置
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class OAuth2WeChatAuthorizationServerConfiguration {

	public static void applyDefaultSecurity(HttpSecurity http) {
		OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(http);
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = OAuth2ConfigurerUtils.getTokenGenerator(http);
		OAuth2WeChatAppletAuthenticationProvider authenticationProvider = new OAuth2WeChatAppletAuthenticationProvider();

		WeChatAppletService weChatAppletService = http.getSharedObject(WeChatAppletService.class);
		if (weChatAppletService == null) {
			weChatAppletService = OAuth2ConfigurerUtils.getOptionalBean(http, WeChatAppletService.class);
			if (weChatAppletService == null) {
				weChatAppletService = new InMemoryWeChatAppletService();
			}
		}

		authenticationProvider.setWeChatAppletService(weChatAppletService);
		authenticationProvider.setAuthorizationService(authorizationService);
		authenticationProvider.setTokenGenerator(tokenGenerator);
		http.authenticationProvider(authenticationProvider);
	}

}
