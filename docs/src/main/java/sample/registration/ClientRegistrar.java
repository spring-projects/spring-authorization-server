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
package sample.registration;

import java.util.List;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;

public class ClientRegistrar {
	// @fold:on
	private final WebClient webClient;

	public ClientRegistrar(WebClient webClient) {
		this.webClient = webClient;
	}
	// @fold:off

	public record ClientRegistrationRequest(	// <1>
			@JsonProperty("client_name") String clientName,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			@JsonProperty("logo_uri") String logoUri,
			List<String> contacts,
			String scope) {
	}

	public record ClientRegistrationResponse(	// <2>
			@JsonProperty("registration_access_token") String registrationAccessToken,
			@JsonProperty("registration_client_uri") String registrationClientUri,
			@JsonProperty("client_name") String clientName,
			@JsonProperty("client_id") String clientId,
			@JsonProperty("client_secret") String clientSecret,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
		 	@JsonProperty("logo_uri") String logoUri,
		 	List<String> contacts,
			String scope) {
	}

	public void exampleRegistration(String initialAccessToken) {	// <3>
		ClientRegistrationRequest clientRegistrationRequest = new ClientRegistrationRequest(	// <4>
				"client-1",
				List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				List.of("https://client.example.org/callback", "https://client.example.org/callback2"),
				"https://client.example.org/logo",
				List.of("contact-1", "contact-2"),
				"openid email profile"
		);

		ClientRegistrationResponse clientRegistrationResponse =
				registerClient(initialAccessToken, clientRegistrationRequest);	// <5>

		assert (clientRegistrationResponse.clientName().contentEquals("client-1"));	// <6>
		assert (!Objects.isNull(clientRegistrationResponse.clientSecret()));
		assert (clientRegistrationResponse.scope().contentEquals("openid profile email"));
		assert (clientRegistrationResponse.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
		assert (clientRegistrationResponse.redirectUris().contains("https://client.example.org/callback"));
		assert (clientRegistrationResponse.redirectUris().contains("https://client.example.org/callback2"));
		assert (!clientRegistrationResponse.registrationAccessToken().isEmpty());
		assert (!clientRegistrationResponse.registrationClientUri().isEmpty());
		assert (clientRegistrationResponse.logoUri().contentEquals("https://client.example.org/logo"));
		assert (clientRegistrationResponse.contacts().size() == 2);
		assert (clientRegistrationResponse.contacts().contains("contact-1"));
		assert (clientRegistrationResponse.contacts().contains("contact-2"));

		String registrationAccessToken = clientRegistrationResponse.registrationAccessToken();	// <7>
		String registrationClientUri = clientRegistrationResponse.registrationClientUri();

		ClientRegistrationResponse retrievedClient = retrieveClient(registrationAccessToken, registrationClientUri);	// <8>

		assert (retrievedClient.clientName().contentEquals("client-1"));	// <9>
		assert (!Objects.isNull(retrievedClient.clientId()));
		assert (!Objects.isNull(retrievedClient.clientSecret()));
		assert (retrievedClient.scope().contentEquals("openid profile email"));
		assert (retrievedClient.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
		assert (retrievedClient.redirectUris().contains("https://client.example.org/callback"));
		assert (retrievedClient.redirectUris().contains("https://client.example.org/callback2"));
		assert (retrievedClient.logoUri().contentEquals("https://client.example.org/logo"));
		assert (retrievedClient.contacts().size() == 2);
		assert (retrievedClient.contacts().contains("contact-1"));
		assert (retrievedClient.contacts().contains("contact-2"));
		assert (Objects.isNull(retrievedClient.registrationAccessToken()));
		assert (!retrievedClient.registrationClientUri().isEmpty());
	}

	public ClientRegistrationResponse registerClient(String initialAccessToken, ClientRegistrationRequest request) {	// <10>
		return this.webClient
				.post()
				.uri("/connect/register")
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(initialAccessToken))
				.body(Mono.just(request), ClientRegistrationRequest.class)
				.retrieve()
				.bodyToMono(ClientRegistrationResponse.class)
				.block();
	}

	public ClientRegistrationResponse retrieveClient(String registrationAccessToken, String registrationClientUri) {	// <11>
		return this.webClient
				.get()
				.uri(registrationClientUri)
				.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(registrationAccessToken))
				.retrieve()
				.bodyToMono(ClientRegistrationResponse.class)
				.block();
	}

}
