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
package sample.authorization;

import java.util.Arrays;

import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
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
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * @author Steve Riesenberg
 * @since 1.1
 */
public final class OAuth2DeviceAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> {

	private RestOperations restOperations;

	public OAuth2DeviceAccessTokenResponseClient() {
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		this.restOperations = restTemplate;
	}

	public void setRestOperations(RestOperations restOperations) {
		this.restOperations = restOperations;
	}

	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2DeviceGrantRequest deviceGrantRequest) {
		ClientRegistration clientRegistration = deviceGrantRequest.getClientRegistration();

		HttpHeaders headers = new HttpHeaders();
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
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		}

		MultiValueMap<String, Object> requestParameters = new LinkedMultiValueMap<>();
		requestParameters.add(OAuth2ParameterNames.GRANT_TYPE, deviceGrantRequest.getGrantType().getValue());
		requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		requestParameters.add(OAuth2ParameterNames.DEVICE_CODE, deviceGrantRequest.getDeviceCode());

		// @formatter:off
		RequestEntity<MultiValueMap<String, Object>> requestEntity =
				RequestEntity.post(deviceGrantRequest.getClientRegistration().getProviderDetails().getTokenUri())
						.headers(headers)
						.body(requestParameters);
		// @formatter:on

		try {
			return this.restOperations.exchange(requestEntity, OAuth2AccessTokenResponse.class).getBody();
		} catch (RestClientException ex) {
			OAuth2Error oauth2Error = new OAuth2Error("invalid_token_response",
					"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
							+ ex.getMessage(), null);
			throw new OAuth2AuthorizationException(oauth2Error, ex);
		}
	}

}
