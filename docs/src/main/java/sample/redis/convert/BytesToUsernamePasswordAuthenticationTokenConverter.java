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

import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.redis.serializer.JacksonJsonRedisSerializer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import tools.jackson.databind.json.JsonMapper;

@ReadingConverter
public class BytesToUsernamePasswordAuthenticationTokenConverter
		implements Converter<byte[], UsernamePasswordAuthenticationToken> {

	private final JacksonJsonRedisSerializer<UsernamePasswordAuthenticationToken> serializer;

	public BytesToUsernamePasswordAuthenticationTokenConverter() {
		JsonMapper objectMapper = JsonMapper.builder()
				.addModules(SecurityJacksonModules.getModules(BytesToUsernamePasswordAuthenticationTokenConverter.class.getClassLoader()))
				.addModule(new OAuth2AuthorizationServerJacksonModule())
				.build();;
		this.serializer = new JacksonJsonRedisSerializer<>(objectMapper, UsernamePasswordAuthenticationToken.class);
	}

	@Override
	public UsernamePasswordAuthenticationToken convert(byte[] value) {
		return this.serializer.deserialize(value);
	}

}
