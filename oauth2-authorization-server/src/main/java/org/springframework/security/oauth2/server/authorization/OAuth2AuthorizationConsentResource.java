/*
 * Copyright 2022 the original author or authors.
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

import java.util.Set;

/**
 * Resource containing the data of an {@link OAuth2AuthorizationConsent} object.
 *
 * @author Steve Riesenberg
 * @since 0.2.2
 */
public class OAuth2AuthorizationConsentResource {
	private String registeredClientId;
	private String principalName;
	private Set<String> authorities;

	public String getRegisteredClientId() {
		return registeredClientId;
	}

	public void setRegisteredClientId(String registeredClientId) {
		this.registeredClientId = registeredClientId;
	}

	public String getPrincipalName() {
		return principalName;
	}

	public void setPrincipalName(String principalName) {
		this.principalName = principalName;
	}

	public Set<String> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Set<String> authorities) {
		this.authorities = authorities;
	}
}
