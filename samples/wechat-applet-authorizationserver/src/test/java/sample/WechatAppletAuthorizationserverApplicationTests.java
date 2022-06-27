package sample;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

class WechatAppletAuthorizationserverApplicationTests {

	@Test
	void contextLoads() {

		String appid = "微信小程序ID，如：wxcf4f3a217a******";
		String code = "微信授权code";
		String clientId = "client";
		String clientSecret = "secret";

		Map<String, String> map = new HashMap<>();
		map.put("grant_type", "wechat_applet");
		map.put("client_id", clientId);
		map.put("client_secret", clientSecret);
		map.put("appid", appid);
		map.put("code", code);

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<?> httpEntity = new HttpEntity<>(httpHeaders);

		String url = "http://127.0.0.1:9080/oauth2/token?grant_type={grant_type}&client_id={client_id}&client_secret={client_secret}&appid={appid}&code={code}";
		String postForObject = restTemplate.postForObject(url, httpEntity, String.class, map);

		System.out.println("授权信息：" + postForObject);
	}

}
