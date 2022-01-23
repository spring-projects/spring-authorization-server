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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.junit.Test;
import org.springframework.security.config.annotation.ObjectPostProcessor;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class OAuth2ClientAuthenticationConfigurerTest {

	@Test
	public void assertionWhenAuthenticationProviderNull() {
		ObjectPostProcessor<Object> opp = new ObjectPostProcessor<Object>() {
			@Override
			public <O> O postProcess(O object) {
				return null;
			}
		};

		OAuth2ClientAuthenticationConfigurer configurer =
				new OAuth2ClientAuthenticationConfigurer(opp);

		assertThatThrownBy(() -> {
			configurer.authenticationProvider(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessage("AuthenticationProvider cannot be null");
	}
}
