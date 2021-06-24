/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.jackson2;

import java.util.Collections;
import java.util.HashSet;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

/**
 * Jackson {@code Module} for {@code spring-authorization-server}, that registers the
 * following mix-in annotations:
 *
 * <ul>
 * <li>{@link UnmodifiableMapMixin}</li>
 * <li>{@link HashSetMixin}</li>
 * <li>{@link OAuth2AuthorizationRequestMixin}</li>
 * <li>{@link OAuth2ClientAuthenticationTokenMixin}</li>
 * </ul>
 *
 * If not already enabled, default typing will be automatically enabled as type info is
 * required to properly serialize/deserialize objects. In order to use this module just
 * add it to your {@code ObjectMapper} configuration.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new OAuth2ServerJackson2Module());
 * </pre>
 *
 * @author Steve Riesenberg
 * @since 0.1.2
 * @see SecurityJackson2Modules
 * @see UnmodifiableMapMixin
 * @see HashSetMixin
 * @see OAuth2AuthorizationRequestMixin
 * @see OAuth2ClientAuthenticationTokenMixin
 */
public class OAuth2ServerJackson2Module extends SimpleModule {

	public OAuth2ServerJackson2Module() {
		super(OAuth2ServerJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
		context.setMixInAnnotations(Collections.unmodifiableMap(Collections.emptyMap()).getClass(),
				UnmodifiableMapMixin.class);
		context.setMixInAnnotations(HashSet.class, HashSetMixin.class);
		context.setMixInAnnotations(OAuth2AuthorizationRequest.class, OAuth2AuthorizationRequestMixin.class);
		context.setMixInAnnotations(OAuth2ClientAuthenticationToken.class, OAuth2ClientAuthenticationTokenMixin.class);
	}

}
