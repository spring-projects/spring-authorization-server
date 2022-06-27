package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * 微信小程序 账户服务接口
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public interface WeChatAppletService {

	/**
	 * 根据 微信小程序的账户ID，查询秘钥
	 * @param appid 微信小程序的账户ID
	 * @return 返回 微信小程序秘钥
	 */
	String getSecretByAppid(String appid);

	/**
	 * 认证信息
	 * @param appid 微信小程序的账户ID
	 * @param openid 用户唯一标识
	 * @param unionid 用户在开放平台的唯一标识符，若当前小程序已绑定到微信开放平台帐号下会返回，详见 <a href=
	 * "https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/union-id.html">UnionID
	 * 机制说明</a>。
	 * @param sessionKey 会话密钥
	 * @param details 登录信息
	 * @return 返回 认证信息
	 */
	AbstractAuthenticationToken authenticationToken(String appid, String openid, String unionid, String sessionKey,
			Object details);

}
