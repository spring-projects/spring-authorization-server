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

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Steve Riesenberg
 * @since 1.1
 */
@Controller
public class DeviceController {

	private static final Set<String> DEVICE_GRANT_ERRORS = new HashSet<>(Arrays.asList(
			"authorization_pending",
			"slow_down",
			"access_denied",
			"expired_token"
	));

	private static final ParameterizedTypeReference<Map<String, Object>> TYPE_REFERENCE =
			new ParameterizedTypeReference<>() {};

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final WebClient webClient;

	private final String messagesBaseUri;

	public DeviceController(
			ClientRegistrationRepository clientRegistrationRepository,
			@Qualifier("default-client-web-client") WebClient webClient,
			@Value("${messages.base-uri}") String messagesBaseUri) {

		this.clientRegistrationRepository = clientRegistrationRepository;
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping("/device_authorize")
	public String authorize(Model model) {
		// @formatter:off
		ClientRegistration clientRegistration =
				this.clientRegistrationRepository.findByRegistrationId(
						"messaging-client-device-code");
		// @formatter:on

		MultiValueMap<String, String> requestParameters = new LinkedMultiValueMap<>();
		requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		requestParameters.add(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(
				clientRegistration.getScopes(), " "));

		String deviceAuthorizationUri = (String) clientRegistration.getProviderDetails().getConfigurationMetadata().get("device_authorization_endpoint");

		// @formatter:off
		Map<String, Object> responseParameters =
				this.webClient.post()
						.uri(deviceAuthorizationUri)
						.headers(headers -> {
							/*
							 * This sample demonstrates the use of a public client that does not
							 * store credentials or authenticate with the authorization server.
							 *
							 * See DeviceClientAuthenticationProvider in the authorization server
							 * sample for an example customization that allows public clients.
							 *
							 * For a confidential client, change the client-authentication-method to
							 * client_secret_basic and set the client-secret to send the
							 * OAuth 2.0 Device Authorization Request with a clientId/clientSecret.
							 */
							if (!clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
								headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
							}
						})
						.contentType(MediaType.APPLICATION_FORM_URLENCODED)
						.body(BodyInserters.fromFormData(requestParameters))
						.retrieve()
						.bodyToMono(TYPE_REFERENCE)
						.block();
		// @formatter:on

		Objects.requireNonNull(responseParameters, "Device Authorization Response cannot be null");
		Instant issuedAt = Instant.now();
		Integer expiresIn = (Integer) responseParameters.get(OAuth2ParameterNames.EXPIRES_IN);
		Instant expiresAt = issuedAt.plusSeconds(expiresIn);

		model.addAttribute("deviceCode", responseParameters.get(OAuth2ParameterNames.DEVICE_CODE));
		model.addAttribute("expiresAt", expiresAt);
		model.addAttribute("userCode", responseParameters.get(OAuth2ParameterNames.USER_CODE));
		model.addAttribute("verificationUri", responseParameters.get(OAuth2ParameterNames.VERIFICATION_URI));
		// Note: You could use a QR-code to display this URL
		model.addAttribute("verificationUriComplete", responseParameters.get(
				OAuth2ParameterNames.VERIFICATION_URI_COMPLETE));

		return "device-authorize";
	}

	/**
	 * @see #handleError(OAuth2AuthorizationException)
	 */
	@PostMapping("/device_authorize")
	public ResponseEntity<Void> poll(@RequestParam(OAuth2ParameterNames.DEVICE_CODE) String deviceCode,
			@RegisteredOAuth2AuthorizedClient("messaging-client-device-code")
					OAuth2AuthorizedClient authorizedClient) {

		/*
		 * The client will repeatedly poll until authorization is granted.
		 *
		 * The OAuth2AuthorizedClientManager uses the device_code parameter
		 * to make a token request, which returns authorization_pending until
		 * the user has granted authorization.
		 *
		 * If the user has denied authorization, access_denied is returned and
		 * polling should stop.
		 *
		 * If the device code expires, expired_token is returned and polling
		 * should stop.
		 *
		 * This endpoint simply returns 200 OK when the client is authorized.
		 */
		return ResponseEntity.status(HttpStatus.OK).build();
	}

	@ExceptionHandler(OAuth2AuthorizationException.class)
	public ResponseEntity<OAuth2Error> handleError(OAuth2AuthorizationException ex) {
		String errorCode = ex.getError().getErrorCode();
		if (DEVICE_GRANT_ERRORS.contains(errorCode)) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getError());
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getError());
	}

	@GetMapping("/device_authorized")
	public String authorized(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-device-code")
					OAuth2AuthorizedClient authorizedClient) {

		String[] messages = this.webClient.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);

		return "index";
	}

}
