package org.springframework.security.oauth2.server.authorization.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2WeChatParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.WeChatAppletService;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2WeChatAppletAuthenticationToken.WECHAT_APPLET;

/**
 * 微信 OAuth2 身份验证提供程序
 *
 * @author xuxiaowei
 * @since 0.0.1
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
public class OAuth2WeChatAppletAuthenticationProvider implements AuthenticationProvider {

	/**
	 * auth.code2Session
	 *
	 * @see <a href=
	 * "https://developers.weixin.qq.com/miniprogram/dev/api-backend/open-api/login/auth.code2Session.html">登录凭证校验</a>
	 */
	public final String JS_CODE2_SESSION_URL = "https://api.weixin.qq.com/sns/jscode2session?appid={appid}&secret={secret}&js_code={js_code}&grant_type=authorization_code";

	private RestTemplate restTemplate = new RestTemplate();

	private WeChatAppletService weChatAppletService;

	private OAuth2AuthorizationService authorizationService;

	private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	public void setAuthorizationService(OAuth2AuthorizationService authorizationService) {
		this.authorizationService = authorizationService;
	}

	public void setWeChatAppletService(WeChatAppletService weChatAppletService) {
		this.weChatAppletService = weChatAppletService;
	}

	public void setTokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		this.tokenGenerator = tokenGenerator;
	}

	public void setRestTemplate(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2WeChatAppletAuthenticationToken oauth2WeChatAppletAuthenticationToken = (OAuth2WeChatAppletAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
				.getAuthenticatedClientElseThrowInvalidClient(oauth2WeChatAppletAuthenticationToken);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (registeredClient == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "客户信息不能为空", null);
			throw new OAuth2AuthenticationException(error);
		}
		Set<String> allowedScopes = registeredClient.getScopes();

		String appid = oauth2WeChatAppletAuthenticationToken.getAppid();
		String code = oauth2WeChatAppletAuthenticationToken.getCode();
		Object details = oauth2WeChatAppletAuthenticationToken.getDetails();
		String scope = oauth2WeChatAppletAuthenticationToken.getScope();
		Set<String> requestedScopes = StringUtils.commaDelimitedListToSet(scope);

		if (requestedScopes.isEmpty()) {
			// 请求中的 scope 为空，允许全部
			requestedScopes = allowedScopes;
		}
		else if (!allowedScopes.containsAll(requestedScopes)) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
					"OAuth 2.0 Parameter: " + OAuth2ParameterNames.SCOPE, null);
			throw new OAuth2AuthenticationException(error);
		}

		Map<String, String> uriVariables = new HashMap<>(8);
		uriVariables.put(OAuth2WeChatParameterNames.APPID, appid);

		String secret = weChatAppletService.getSecretByAppid(appid);

		uriVariables.put(OAuth2WeChatParameterNames.SECRET, secret);

		uriVariables.put(OAuth2WeChatParameterNames.JS_CODE, code);
		String forObject = restTemplate.getForObject(JS_CODE2_SESSION_URL, String.class, uriVariables);

		Code2SessionResponse code2SessionResponse;
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			code2SessionResponse = objectMapper.readValue(forObject, Code2SessionResponse.class);
		}
		catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}

		String openid = code2SessionResponse.getOpenid();
		String unionid = code2SessionResponse.getUnionid();
		String sessionKey = code2SessionResponse.getSessionKey();

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient);
		builder.principalName(openid);
		builder.attribute(OAuth2WeChatParameterNames.OPENID, openid);
		builder.attribute(OAuth2WeChatParameterNames.UNIONID, unionid);
		builder.attribute(OAuth2WeChatParameterNames.APPID, appid);
		builder.authorizationGrantType(WECHAT_APPLET);

		AbstractAuthenticationToken abstractAuthenticationToken = weChatAppletService.authenticationToken(appid, openid,
				unionid, sessionKey, details);

		builder.attribute(Principal.class.getName(), abstractAuthenticationToken);
		builder.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, requestedScopes);

		OAuth2Authorization authorization = builder.build();

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.providerContext(ProviderContextHolder.getProviderContext())
				.authorization(authorization)
				.authorizedScopes(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME))
				.authorizationGrantType(WECHAT_APPLET)
				.authorizationGrant(oauth2WeChatAppletAuthenticationToken);
		// @formatter:on

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", null);
			throw new OAuth2AuthenticationException(error);
		}
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
							((ClaimAccessor) generatedAccessToken).getClaims()));
		}
		else {
			authorizationBuilder.accessToken(accessToken);
		}

		// ----- Refresh token -----
		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
		// Do not issue refresh token to public client
				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", null);
				throw new OAuth2AuthenticationException(error);
			}
			refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(refreshToken);
		}

		authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		Map<String, Object> additionalParameters = Collections.emptyMap();

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken,
				additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2WeChatAppletAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * 登录凭证校验 返回值
	 *
	 * @author xuxiaowei
	 * @see 0.0.1
	 */
	public static class Code2SessionResponse {

		/**
		 * 用户唯一标识
		 */
		private String openid;

		/**
		 * 会话密钥
		 */
		@JsonProperty("session_key")
		private String sessionKey;

		/**
		 * 用户在开放平台的唯一标识符，若当前小程序已绑定到微信开放平台帐号下会返回，详见 <a href=
		 * "https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/union-id.html">UnionID
		 * 机制说明</a>。
		 */
		private String unionid;

		/**
		 * 错误码
		 */
		private String errcode;

		/**
		 * 错误信息
		 */
		private String errmsg;

		public String getOpenid() {
			return openid;
		}

		public void setOpenid(String openid) {
			this.openid = openid;
		}

		public String getSessionKey() {
			return sessionKey;
		}

		public void setSessionKey(String sessionKey) {
			this.sessionKey = sessionKey;
		}

		public String getUnionid() {
			return unionid;
		}

		public void setUnionid(String unionid) {
			this.unionid = unionid;
		}

		public String getErrcode() {
			return errcode;
		}

		public void setErrcode(String errcode) {
			this.errcode = errcode;
		}

		public String getErrmsg() {
			return errmsg;
		}

		public void setErrmsg(String errmsg) {
			this.errmsg = errmsg;
		}

		@Override
		public String toString() {
			return "Code2SessionResponse{" + "openid='" + openid + '\'' + ", sessionKey='" + sessionKey + '\''
					+ ", unionid='" + unionid + '\'' + ", errcode='" + errcode + '\'' + ", errmsg='" + errmsg + '\''
					+ '}';
		}

	}

}
