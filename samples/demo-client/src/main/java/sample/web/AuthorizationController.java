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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@Controller
public class AuthorizationController {
	private final WebClient webClient;
	private final String messagesBaseUri;
	private final String userMessagesBaseUri;

	public AuthorizationController(WebClient webClient,
			@Value("${messages.base-uri}") String messagesBaseUri,
			@Value("${user-messages.base-uri}") String userMessagesBaseUri) {
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
		this.userMessagesBaseUri = userMessagesBaseUri;
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code")
	public String authorizationCodeGrant(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
					OAuth2AuthorizedClient authorizedClient) {

		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);

		return "index";
	}

	// '/authorized' is the registered 'redirect_uri' for authorization_code
	@GetMapping(value = "/authorized", params = OAuth2ParameterNames.ERROR)
	public String authorizationFailed(Model model, HttpServletRequest request) {
		String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
		if (StringUtils.hasText(errorCode)) {
			model.addAttribute("error",
					new OAuth2Error(
							errorCode,
							request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION),
							request.getParameter(OAuth2ParameterNames.ERROR_URI))
			);
		}

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials")
	public String clientCredentialsGrant(Model model) {

		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(clientRegistrationId("messaging-client-client-credentials"))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=token_exchange")
	public String tokenExchangeGrant(Model model) {

		String[] messages = this.webClient
				.get()
				.uri(this.userMessagesBaseUri)
				.attributes(clientRegistrationId("user-client-authorization-code"))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=device_code")
	public String deviceCodeGrant() {
		return "device-activate";
	}

	@ExceptionHandler(WebClientResponseException.class)
	public String handleError(Model model, WebClientResponseException ex) {
		model.addAttribute("error", ex.getMessage());
		return "index";
	}

}
