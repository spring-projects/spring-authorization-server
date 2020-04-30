/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Joe Grandja
 * @author Paurav Munshi
 */
public class OAuth2Authorization {
	private String registeredClientId;
	private String principalName;
	private OAuth2AccessToken accessToken;
	private Map<String, Object> attributes;
	
	public String getRegisteredClientId() {
		return registeredClientId;
	}
	public String getPrincipalName() {
		return principalName;
	}
	public OAuth2AccessToken getAccessToken() {
		return accessToken;
	}
	public Object getAttribute(String attributeKey) {
		return attributes.get(attributeKey);
	}
	public static Builder createBuilder() {
		return new Builder();
	}
	
	public static class Builder {
		private String registeredClientId;
		private String principalName;
		private OAuth2AccessToken accessToken;
		private Map<String, Object> attributes;
		
		private Builder() {
			this.attributes = new HashMap<String,Object>();
		}
		
		public Builder clientId(String clientId) {
			this.registeredClientId = clientId;
			return this;
		}
		
		public Builder principalName(String principalName) {
			this.principalName = principalName;
			return this;
		}
		
		public Builder accessToken(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			return this;
		}
		public Builder addAttribute(String key, Object value) {
			this.attributes.put(key, value);
			return this;
		}
		
		public OAuth2Authorization build() {
			OAuth2Authorization authorization = new OAuth2Authorization();
			authorization.registeredClientId = this.registeredClientId;
			authorization.principalName = this.principalName;
			authorization.accessToken = this.accessToken;
			authorization.attributes = this.attributes;
			
			return authorization;
		}
	}

}
