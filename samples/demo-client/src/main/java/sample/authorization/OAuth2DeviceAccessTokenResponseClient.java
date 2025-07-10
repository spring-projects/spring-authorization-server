/*
 * Copyright 2020-2025 the original author or authors.
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

import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * @author Steve Riesenberg
 * @since 1.1
 */
public final class OAuth2DeviceAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> {

	private RestClient restClient;

	public OAuth2DeviceAccessTokenResponseClient() {
		// @formatter:off
		this.restClient = RestClient.builder()
				.messageConverters((messageConverters) -> {
					messageConverters.clear();
					messageConverters.add(new FormHttpMessageConverter());
					messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
				})
				.defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
				.build();
		// @formatter:on
	}

	public void setRestClient(RestClient restClient) {
		this.restClient = restClient;
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2DeviceGrantRequest deviceGrantRequest) {
		ClientRegistration clientRegistration = deviceGrantRequest.getClientRegistration();

		HttpHeaders headerParameters = new HttpHeaders();
		/*
		 * This sample demonstrates the use of a public client that does not
		 * store credentials or authenticate with the authorization server.
		 *
		 * See DeviceClientAuthenticationProvider in the authorization server
		 * sample for an example customization that allows public clients.
		 *
		 * For a confidential client, change the client-authentication-method
		 * to client_secret_basic and set the client-secret to send the
		 * OAuth 2.0 Token Request with a clientId/clientSecret.
		 */
		if (!clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
			headerParameters.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		}

		MultiValueMap<String, Object> requestParameters = new LinkedMultiValueMap<>();
		requestParameters.add(OAuth2ParameterNames.GRANT_TYPE, deviceGrantRequest.getGrantType().getValue());
		requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		requestParameters.add(OAuth2ParameterNames.DEVICE_CODE, deviceGrantRequest.getDeviceCode());

		try {
			// @formatter:off
			return this.restClient.post()
					.uri(deviceGrantRequest.getClientRegistration().getProviderDetails().getTokenUri())
					.headers((headers) -> headers.putAll(headerParameters))
					.body(requestParameters)
					.retrieve()
					.body(OAuth2AccessTokenResponse.class);
			// @formatter:on
		} catch (RestClientException ex) {
			OAuth2Error oauth2Error = new OAuth2Error("invalid_token_response",
					"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
							+ ex.getMessage(), null);
			throw new OAuth2AuthorizationException(oauth2Error, ex);
		}
	}

}
