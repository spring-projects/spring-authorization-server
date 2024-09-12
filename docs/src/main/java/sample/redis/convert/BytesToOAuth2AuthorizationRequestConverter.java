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
package sample.redis.convert;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

@ReadingConverter
public class BytesToOAuth2AuthorizationRequestConverter implements Converter<byte[], OAuth2AuthorizationRequest> {

	private final Jackson2JsonRedisSerializer<OAuth2AuthorizationRequest> serializer;

	public BytesToOAuth2AuthorizationRequestConverter() {
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.registerModules(
				SecurityJackson2Modules.getModules(BytesToOAuth2AuthorizationRequestConverter.class.getClassLoader()));
		objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		this.serializer = new Jackson2JsonRedisSerializer<>(objectMapper, OAuth2AuthorizationRequest.class);
	}

	@Override
	public OAuth2AuthorizationRequest convert(byte[] value) {
		return this.serializer.deserialize(value);
	}

}
