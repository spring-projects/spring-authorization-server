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
package sample.userinfo.idtoken;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

/**
 * Example service to perform lookup of user info for customizing an {@code id_token}.
 */
@Service
public class OidcUserInfoService {

	private final UserInfoRepository userInfoRepository = new UserInfoRepository();

	public OidcUserInfo loadUser(String username) {
		return new OidcUserInfo(this.userInfoRepository.findByUsername(username));
	}

	static class UserInfoRepository {

		private final Map<String, Map<String, Object>> userInfo = new HashMap<>();

		public UserInfoRepository() {
			this.userInfo.put("user1", createUser("user1"));
			this.userInfo.put("user2", createUser("user2"));
		}

		public Map<String, Object> findByUsername(String username) {
			return this.userInfo.get(username);
		}

		private static Map<String, Object> createUser(String username) {
			return OidcUserInfo.builder()
					.subject(username)
					.name("First Last")
					.givenName("First")
					.familyName("Last")
					.middleName("Middle")
					.nickname("User")
					.preferredUsername(username)
					.profile("https://example.com/" + username)
					.picture("https://example.com/" + username + ".jpg")
					.website("https://example.com")
					.email(username + "@example.com")
					.emailVerified(true)
					.gender("female")
					.birthdate("1970-01-01")
					.zoneinfo("Europe/Paris")
					.locale("en-US")
					.phoneNumber("+1 (604) 555-1234;ext=5678")
					.phoneNumberVerified(false)
					.claim("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
					.updatedAt("1970-01-01T00:00:00Z")
					.build()
					.getClaims();
		}
	}

}
