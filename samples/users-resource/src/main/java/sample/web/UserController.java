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
package sample.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
@RestController
public class UserController {

	private final RestClient restClient;

	public UserController(@Value("${messages.base-uri}") String baseUrl) {
		this.restClient = RestClient.builder()
				.baseUrl(baseUrl)
				.build();
	}

	@GetMapping(value = "/user/messages", params = "use_case=delegation")
	public List<String> getMessagesWithDelegation(
			@RegisteredOAuth2AuthorizedClient("messaging-client-token-exchange-with-delegation")
					OAuth2AuthorizedClient authorizedClient) {
		return getUserMessages(authorizedClient);
	}

	@GetMapping(value = "/user/messages", params = "use_case=impersonation")
	public List<String> getMessagesWithImpersonation(
			@RegisteredOAuth2AuthorizedClient("messaging-client-token-exchange-with-impersonation")
					OAuth2AuthorizedClient authorizedClient) {
		return getUserMessages(authorizedClient);
	}

	private List<String> getUserMessages(OAuth2AuthorizedClient authorizedClient) {
		// @formatter:off
		String[] messages = Objects.requireNonNull(
				this.restClient.get()
						.uri("/messages")
						.headers((headers) -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
						.retrieve()
						.body(String[].class)
		);
		// @formatter:on

		List<String> userMessages = new ArrayList<>(Arrays.asList(messages));
		userMessages.add("%s has %d unread messages".formatted(authorizedClient.getPrincipalName(), messages.length));

		return userMessages;
	}

}
