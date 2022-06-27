package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * 微信 OAuth2 用于验证授权授予的 。
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken 用于 OAuth 2.0 授权代码授予的
 * {@link Authentication} 实现。
 * @see OAuth2RefreshTokenAuthenticationToken 用于 OAuth 2.0 刷新令牌授予的 {@link Authentication}
 * 实现。
 * @see OAuth2ClientCredentialsAuthenticationToken 用于 OAuth 2.0 客户端凭据授予的
 * {@link Authentication} 实现。
 */
public class OAuth2WeChatAppletAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	public static final AuthorizationGrantType WECHAT_APPLET = new AuthorizationGrantType("wechat_applet");

	private final String appid;

	private final String code;

	private final String scope;

	/**
	 * 子类构造函数
	 * @param appid 微信小程序的账户ID
	 * @param code 微信小程序授权码
	 * @param scope 授权范围
	 * @param clientPrincipal 经过身份验证的客户端主体
	 * @param additionalParameters 附加参数
	 */
	public OAuth2WeChatAppletAuthenticationToken(String appid, String code, String scope,
			Authentication clientPrincipal, Map<String, Object> additionalParameters) {
		super(WECHAT_APPLET, clientPrincipal, additionalParameters);
		Assert.hasText(code, "appid cannot be empty");
		Assert.hasText(code, "code cannot be empty");
		this.appid = appid;
		this.code = code;
		this.scope = scope;
	}

	public String getAppid() {
		return appid;
	}

	public String getCode() {
		return code;
	}

	public String getScope() {
		return scope;
	}

}
