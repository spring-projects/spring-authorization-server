package org.springframework.security.oauth2.core.endpoint;

/**
 * 微信小程序 参数名
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public interface OAuth2WeChatParameterNames {

	/**
	 * 微信小程序的账户ID参数名
	 */
	String APPID = "appid";

	/**
	 * 微信小程序的秘钥参数名
	 */
	String SECRET = "secret";

	/**
	 * 微信小程序授权码参数名
	 */
	String JS_CODE = "js_code";

	/**
	 * 用户唯一标识
	 */
	String OPENID = "openid";

	/**
	 * 用户在开放平台的唯一标识符，若当前小程序已绑定到微信开放平台帐号下会返回，详见 <a href=
	 * "https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/union-id.html">UnionID
	 * 机制说明</a>。
	 */
	String UNIONID = "unionid";

	/**
	 * 范围
	 */
	String SCOPE = "scope";

}
