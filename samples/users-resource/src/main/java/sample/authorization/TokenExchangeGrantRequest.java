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
package sample.authorization;

import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
public final class TokenExchangeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	static final AuthorizationGrantType TOKEN_EXCHANGE = new AuthorizationGrantType(
			"urn:ietf:params:oauth:grant-type:token-exchange");

	private final String subjectToken;

	private final String actorToken;

	public TokenExchangeGrantRequest(ClientRegistration clientRegistration, String subjectToken,
			String actorToken) {
		super(TOKEN_EXCHANGE, clientRegistration);
		Assert.hasText(subjectToken, "subjectToken cannot be empty");
		if (actorToken != null) {
			Assert.hasText(actorToken, "actorToken cannot be empty");
		}
		this.subjectToken = subjectToken;
		this.actorToken = actorToken;
	}

	public String getSubjectToken() {
		return this.subjectToken;
	}

	public String getActorToken() {
		return this.actorToken;
	}
}