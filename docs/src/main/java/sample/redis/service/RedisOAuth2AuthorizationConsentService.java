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
package sample.redis.service;

import sample.redis.entity.OAuth2UserConsent;
import sample.redis.repository.OAuth2UserConsentRepository;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.util.Assert;

public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	private final OAuth2UserConsentRepository userConsentRepository;

	public RedisOAuth2AuthorizationConsentService(OAuth2UserConsentRepository userConsentRepository) {
		Assert.notNull(userConsentRepository, "userConsentRepository cannot be null");
		this.userConsentRepository = userConsentRepository;
	}

	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		OAuth2UserConsent oauth2UserConsent = ModelMapper.convertOAuth2UserConsent(authorizationConsent);
		this.userConsentRepository.save(oauth2UserConsent);
	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		this.userConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
				authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
	}

	@Nullable
	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		OAuth2UserConsent oauth2UserConsent = this.userConsentRepository
			.findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName);
		return oauth2UserConsent != null ? ModelMapper.convertOAuth2AuthorizationConsent(oauth2UserConsent) : null;
	}

}
