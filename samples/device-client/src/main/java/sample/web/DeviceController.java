/*
 * Copyright 2020-2023 the original author or authors.
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
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
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

	private static final ParameterizedTypeReference<Map<String, Object>> TYPE_REFERENCE =
			new ParameterizedTypeReference<>() {};

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final WebClient webClient;

	private final String messagesBaseUri;

	private final SecurityContextRepository securityContextRepository =
			new HttpSessionSecurityContextRepository();

	private final SecurityContextHolderStrategy securityContextHolderStrategy =
			SecurityContextHolder.getContextHolderStrategy();

	public DeviceController(ClientRegistrationRepository clientRegistrationRepository, WebClient webClient,
			@Value("${messages.base-uri}") String messagesBaseUri) {

		this.clientRegistrationRepository = clientRegistrationRepository;
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping("/authorize")
	public String authorize(Model model, HttpServletRequest request, HttpServletResponse response) {
		// @formatter:off
		ClientRegistration clientRegistration =
				this.clientRegistrationRepository.findByRegistrationId(
						"messaging-client-device-grant");
		// @formatter:on

		MultiValueMap<String, String> requestParameters = new LinkedMultiValueMap<>();
		requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		requestParameters.add(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(
				clientRegistration.getScopes(), " "));

		// @formatter:off
		Map<String, Object> responseParameters =
				this.webClient.post()
						.uri(clientRegistration.getProviderDetails().getAuthorizationUri())
						.headers(headers -> headers.setBasicAuth(clientRegistration.getClientId(),
								clientRegistration.getClientSecret()))
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
		String deviceCodeValue = (String) responseParameters.get(OAuth2ParameterNames.DEVICE_CODE);

		OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(deviceCodeValue, issuedAt, expiresAt);
		saveSecurityContext(deviceCode, request, response);

		model.addAttribute("deviceCode", deviceCode.getTokenValue());
		model.addAttribute("expiresAt", deviceCode.getExpiresAt());
		model.addAttribute("userCode", responseParameters.get(OAuth2ParameterNames.USER_CODE));
		model.addAttribute("verificationUri", responseParameters.get(OAuth2ParameterNames.VERIFICATION_URI));
		// Note: You could use a QR-code to display this URL
		model.addAttribute("verificationUriComplete", responseParameters.get(
				OAuth2ParameterNames.VERIFICATION_URI_COMPLETE));

		return "authorize";
	}

	/**
	 * @see DeviceControllerAdvice
	 */
	@PostMapping("/authorize")
	public ResponseEntity<Void> poll(@RequestParam(OAuth2ParameterNames.DEVICE_CODE) String deviceCode,
			@RegisteredOAuth2AuthorizedClient("messaging-client-device-grant")
					OAuth2AuthorizedClient authorizedClient) {

		// The client will repeatedly poll until authorization is granted.
		//
		// The OAuth2AuthorizedClientManager uses the device_code parameter
		// to make a token request, which returns authorization_pending until
		// the user has granted authorization.
		//
		// If the user has denied authorization, access_denied is returned and
		// polling should stop.
		//
		// If the device code expires, expired_token is returned and polling
		// should stop.
		//
		// This endpoint simply returns 200 OK when client is authorized.
		return ResponseEntity.status(HttpStatus.OK).build();
	}

	@GetMapping("/authorized")
	public String authorized(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-device-grant")
					OAuth2AuthorizedClient authorizedClient) {

		String[] messages = this.webClient.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);

		return "authorized";
	}

	private void saveSecurityContext(OAuth2DeviceCode deviceCode, HttpServletRequest request,
			HttpServletResponse response) {

		// @formatter:off
		UsernamePasswordAuthenticationToken deviceAuthentication =
				UsernamePasswordAuthenticationToken.authenticated(
						deviceCode, null, AuthorityUtils.createAuthorityList("ROLE_DEVICE"));
		// @formatter:on

		SecurityContext securityContext = this.securityContextHolderStrategy.createEmptyContext();
		securityContext.setAuthentication(deviceAuthentication);
		this.securityContextHolderStrategy.setContext(securityContext);
		this.securityContextRepository.saveContext(securityContext, request, response);
	}

}
