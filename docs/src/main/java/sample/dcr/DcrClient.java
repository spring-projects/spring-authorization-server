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
package sample.dcr;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Objects;

public class DcrClient {
	// @fold:on
	private final WebClient webClient;

	public DcrClient(final WebClient webClient) {
		this.webClient = webClient;
	}
	// @fold:off

	public record DcrRequest( // <1>
			@JsonProperty("client_name") String clientName,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			String scope) {
	}

	public record DcrResponse( // <2>
			@JsonProperty("registration_access_token") String registrationAccessToken,
			@JsonProperty("registration_client_uri") String registrationClientUri,
			@JsonProperty("client_name") String clientName,
			@JsonProperty("client_secret") String clientSecret,
			@JsonProperty("grant_types") List<String> grantTypes,
			@JsonProperty("redirect_uris") List<String> redirectUris,
			String scope) {
	}

	public static final DcrRequest SAMPLE_CLIENT_REGISTRATION_REQUEST = new DcrRequest( // <3>
			"client-1",
			List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
			List.of("https://client.example.org/callback", "https://client.example.org/callback2"),
			"openid email profile"
	);

	public void exampleRegistration(String initialAccessToken) { // <4>
		DcrResponse clientRegistrationResponse =
				this.registerClient(initialAccessToken, SAMPLE_CLIENT_REGISTRATION_REQUEST); // <5>

		assert (clientRegistrationResponse.clientName().contentEquals("client-1")); // <6>
		assert (!Objects.isNull(clientRegistrationResponse.clientSecret()));
		assert (clientRegistrationResponse.scope().contentEquals("openid profile email"));
		assert (clientRegistrationResponse.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
		assert (clientRegistrationResponse.redirectUris().contains("https://client.example.org/callback"));
		assert (clientRegistrationResponse.redirectUris().contains("https://client.example.org/callback2"));
		assert (!clientRegistrationResponse.registrationAccessToken().isEmpty());
		assert (!clientRegistrationResponse.registrationClientUri().isEmpty());

		String registrationAccessToken = clientRegistrationResponse.registrationAccessToken(); // <7>
		String registrationClientUri = clientRegistrationResponse.registrationClientUri();

		DcrResponse retrievedClient = this.retrieveClient(registrationAccessToken, registrationClientUri); // <8>

		assert (retrievedClient.clientName().contentEquals("client-1")); // <9>
		assert (!Objects.isNull(retrievedClient.clientSecret()));
		assert (retrievedClient.scope().contentEquals("openid profile email"));
		assert (retrievedClient.grantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
		assert (retrievedClient.redirectUris().contains("https://client.example.org/callback"));
		assert (retrievedClient.redirectUris().contains("https://client.example.org/callback2"));
		assert (Objects.isNull(retrievedClient.registrationAccessToken()));
		assert (!retrievedClient.registrationClientUri().isEmpty());
	}

	public DcrResponse registerClient(String initialAccessToken, DcrRequest request) { // <10>
		return this.webClient
				.post()
				.uri("/connect/register")
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(initialAccessToken))
				.body(Mono.just(request), DcrRequest.class)
				.retrieve()
				.bodyToMono(DcrResponse.class)
				.block();
	}

	public DcrResponse retrieveClient(String registrationAccessToken, String registrationClientUri) { // <11>
		return this.webClient
				.get()
				.uri(registrationClientUri)
				.header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(registrationAccessToken))
				.retrieve()
				.bodyToMono(DcrResponse.class)
				.block();
	}
}
