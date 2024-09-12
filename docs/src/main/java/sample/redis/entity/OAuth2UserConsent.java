/*
 * Copyright 2020-2024 the original author or authors.
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
package sample.redis.entity;

import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.core.GrantedAuthority;

@RedisHash("oauth2_authorization_consent")
public class OAuth2UserConsent {

	@Id
	private final String id;

	@Indexed
	private final String registeredClientId;

	@Indexed
	private final String principalName;

	private final Set<GrantedAuthority> authorities;

	// @fold:on
	public OAuth2UserConsent(String id, String registeredClientId, String principalName,
			Set<GrantedAuthority> authorities) {
		this.id = id;
		this.registeredClientId = registeredClientId;
		this.principalName = principalName;
		this.authorities = authorities;
	}

	public String getId() {
		return this.id;
	}

	public String getRegisteredClientId() {
		return this.registeredClientId;
	}

	public String getPrincipalName() {
		return this.principalName;
	}

	public Set<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}
	// @fold:off

}
