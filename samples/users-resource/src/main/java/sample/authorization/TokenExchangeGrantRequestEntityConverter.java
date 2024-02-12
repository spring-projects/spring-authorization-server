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

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
public class TokenExchangeGrantRequestEntityConverter implements Converter<TokenExchangeGrantRequest, RequestEntity<?>> {

	private static final String REQUESTED_TOKEN_TYPE = "requested_token_type";

	private static final String SUBJECT_TOKEN = "subject_token";

	private static final String SUBJECT_TOKEN_TYPE = "subject_token_type";

	private static final String ACTOR_TOKEN = "actor_token";

	private static final String ACTOR_TOKEN_TYPE = "actor_token_type";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	@Override
	public RequestEntity<?> convert(TokenExchangeGrantRequest grantRequest) {
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();

		HttpHeaders headers = new HttpHeaders();
		if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		}

		MultiValueMap<String, Object> requestParameters = new LinkedMultiValueMap<>();
		requestParameters.add(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().getValue());
		requestParameters.add(REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		requestParameters.add(SUBJECT_TOKEN, grantRequest.getSubjectToken());
		requestParameters.add(SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		if (StringUtils.hasText(grantRequest.getActorToken())) {
			requestParameters.add(ACTOR_TOKEN, grantRequest.getActorToken());
			requestParameters.add(ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		}
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			requestParameters.add(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		}
		if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
			requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			requestParameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}

		String tokenEndpointUri = clientRegistration.getProviderDetails().getTokenUri();
		return RequestEntity.post(tokenEndpointUri).headers(headers).body(requestParameters);
	}

}
