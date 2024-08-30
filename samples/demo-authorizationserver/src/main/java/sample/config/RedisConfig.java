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
package sample.config;

import java.util.Arrays;

import sample.data.redis.RedisOAuth2AuthorizationConsentService;
import sample.data.redis.RedisOAuth2AuthorizationService;
import sample.data.redis.RedisRegisteredClientRepository;
import sample.data.redis.convert.BytesToClaimsHolderConverter;
import sample.data.redis.convert.BytesToOAuth2AuthorizationRequestConverter;
import sample.data.redis.convert.BytesToUsernamePasswordAuthenticationTokenConverter;
import sample.data.redis.convert.ClaimsHolderToBytesConverter;
import sample.data.redis.convert.OAuth2AuthorizationRequestToBytesConverter;
import sample.data.redis.convert.UsernamePasswordAuthenticationTokenToBytesConverter;
import sample.data.redis.repository.OAuth2AuthorizationGrantAuthorizationRepository;
import sample.data.redis.repository.OAuth2RegisteredClientRepository;
import sample.data.redis.repository.OAuth2UserConsentRepository;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.convert.RedisCustomConversions;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * @author Joe Grandja
 * @since 1.4
 */
@Profile("redis")
@Configuration(proxyBeanMethods = false)
public class RedisConfig {

	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		return new JedisConnectionFactory();
	}

	@Bean
	public RedisTemplate<?, ?> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
		RedisTemplate<byte[], byte[]> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(redisConnectionFactory);
		return redisTemplate;
	}

	@Bean
	public RedisCustomConversions redisCustomConversions() {
		return new RedisCustomConversions(Arrays.asList(new UsernamePasswordAuthenticationTokenToBytesConverter(),
				new BytesToUsernamePasswordAuthenticationTokenConverter(),
				new OAuth2AuthorizationRequestToBytesConverter(), new BytesToOAuth2AuthorizationRequestConverter(),
				new ClaimsHolderToBytesConverter(), new BytesToClaimsHolderConverter()));
	}

	@Bean
	public RedisRegisteredClientRepository registeredClientRepository(
			OAuth2RegisteredClientRepository registeredClientRepository) {
		RedisRegisteredClientRepository redisRegisteredClientRepository = new RedisRegisteredClientRepository(registeredClientRepository);
		RegisteredClients.defaults().forEach(redisRegisteredClientRepository::save);
		return redisRegisteredClientRepository;
	}

	@Bean
	public RedisOAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationGrantAuthorizationRepository authorizationGrantAuthorizationRepository) {
		return new RedisOAuth2AuthorizationService(registeredClientRepository,
				authorizationGrantAuthorizationRepository);
	}

	@Bean
	public RedisOAuth2AuthorizationConsentService authorizationConsentService(
			OAuth2UserConsentRepository userConsentRepository) {
		return new RedisOAuth2AuthorizationConsentService(userConsentRepository);
	}

}
