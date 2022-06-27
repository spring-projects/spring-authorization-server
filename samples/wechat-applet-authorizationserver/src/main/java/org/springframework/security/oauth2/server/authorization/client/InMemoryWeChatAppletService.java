package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.authorization.client.WeChatAppletService;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

/**
 * 微信小程序 账户服务接口
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class InMemoryWeChatAppletService implements WeChatAppletService {

	private List<WeChatApplet> weChatAppletList = new ArrayList<>();

	public void setWeChatAppletList(List<WeChatApplet> weChatAppletList) {
		this.weChatAppletList = weChatAppletList;
	}

	/**
	 * 根据 微信小程序的账户ID，查询秘钥
	 * @param appid 微信小程序的账户ID
	 * @return 返回 微信小程序秘钥
	 */
	@Override
	public String getSecretByAppid(String appid) {
		Assert.notNull(appid, "appid 不能为 null");
		for (WeChatApplet weChatApplet : weChatAppletList) {
			if (appid.equals(weChatApplet.getAppid())) {
				return weChatApplet.getSecret();
			}
		}
		throw new IllegalArgumentException("未找到 secret");
	}

	/**
	 * 认证信息
	 * @param appid 微信小程序的账户ID
	 * @param openid 用户唯一标识
	 * @param unionid 用户在开放平台的唯一标识符，若当前小程序已绑定到微信开放平台帐号下会返回，详见 <a href=
	 * "https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/union-id.html">UnionID
	 * 机制说明</a>。
	 * @param sessionKey 会话密钥
	 * @return 返回 认证信息
	 */
	@Override
	public AbstractAuthenticationToken authenticationToken(String appid, String openid, String unionid,
			String sessionKey, Object details) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("wechat_applet");
		authorities.add(authority);
		User user = new User(openid, sessionKey, authorities);
		return new UsernamePasswordAuthenticationToken(user, details);
	}

	/**
	 * 微信小程序账户
	 *
	 * @author xuxiaowei
	 * @since 0.0.1
	 */
	public static class WeChatApplet {

		/**
		 * 微信小程序账户ID
		 */
		private String appid;

		/**
		 * 微信小程序秘钥
		 */
		private String secret;

		public WeChatApplet() {
		}

		public WeChatApplet(String appid, String secret) {
			this.appid = appid;
			this.secret = secret;
		}

		public String getAppid() {
			return appid;
		}

		public void setAppid(String appid) {
			this.appid = appid;
		}

		public String getSecret() {
			return secret;
		}

		public void setSecret(String secret) {
			this.secret = secret;
		}

		@Override
		public String toString() {
			return "WeChatApplet{" + "appid='" + appid + '\'' + ", secret='" + secret + '\'' + '}';
		}

	}

}
