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
package sample.redis.config;

import java.util.Arrays;

import sample.redis.convert.BytesToClaimsHolderConverter;
import sample.redis.convert.BytesToOAuth2AuthorizationRequestConverter;
import sample.redis.convert.BytesToUsernamePasswordAuthenticationTokenConverter;
import sample.redis.convert.ClaimsHolderToBytesConverter;
import sample.redis.convert.OAuth2AuthorizationRequestToBytesConverter;
import sample.redis.convert.UsernamePasswordAuthenticationTokenToBytesConverter;
import sample.redis.repository.OAuth2AuthorizationGrantAuthorizationRepository;
import sample.redis.repository.OAuth2RegisteredClientRepository;
import sample.redis.repository.OAuth2UserConsentRepository;
import sample.redis.service.RedisOAuth2AuthorizationConsentService;
import sample.redis.service.RedisOAuth2AuthorizationService;
import sample.redis.service.RedisRegisteredClientRepository;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.convert.RedisCustomConversions;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@EnableRedisRepositories("sample.redis.repository")	// <1>
@Configuration(proxyBeanMethods = false)
public class RedisConfig {

	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		return new JedisConnectionFactory();	// <2>
	}

	@Bean
	public RedisTemplate<?, ?> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
		RedisTemplate<byte[], byte[]> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(redisConnectionFactory);
		return redisTemplate;
	}

	@Bean
	public RedisCustomConversions redisCustomConversions() {	// <3>
		return new RedisCustomConversions(Arrays.asList(new UsernamePasswordAuthenticationTokenToBytesConverter(),
				new BytesToUsernamePasswordAuthenticationTokenConverter(),
				new OAuth2AuthorizationRequestToBytesConverter(), new BytesToOAuth2AuthorizationRequestConverter(),
				new ClaimsHolderToBytesConverter(), new BytesToClaimsHolderConverter()));
	}

	@Bean
	public RedisRegisteredClientRepository registeredClientRepository(
			OAuth2RegisteredClientRepository registeredClientRepository) {
		return new RedisRegisteredClientRepository(registeredClientRepository);	// <4>
	}

	@Bean
	public RedisOAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationGrantAuthorizationRepository authorizationGrantAuthorizationRepository) {
		return new RedisOAuth2AuthorizationService(registeredClientRepository,
				authorizationGrantAuthorizationRepository);	// <5>
	}

	@Bean
	public RedisOAuth2AuthorizationConsentService authorizationConsentService(
			OAuth2UserConsentRepository userConsentRepository) {
		return new RedisOAuth2AuthorizationConsentService(userConsentRepository);	// <6>
	}

}
