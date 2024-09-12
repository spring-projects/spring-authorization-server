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
package sample.data.redis.repository;

import org.springframework.data.repository.CrudRepository;
import sample.data.redis.model.OAuth2AuthorizationCodeGrantAuthorization;
import sample.data.redis.model.OAuth2AuthorizationGrantAuthorization;
import sample.data.redis.model.OAuth2DeviceCodeGrantAuthorization;
import sample.data.redis.model.OidcAuthorizationCodeGrantAuthorization;
import org.springframework.stereotype.Repository;

/**
 * @author Joe Grandja
 * @since 1.4
 */
@Repository
public interface OAuth2AuthorizationGrantAuthorizationRepository
		extends CrudRepository<OAuth2AuthorizationGrantAuthorization, String> {

	<T extends OAuth2AuthorizationCodeGrantAuthorization> T findByState(String token);

	<T extends OAuth2AuthorizationCodeGrantAuthorization> T findByAuthorizationCode_TokenValue(String token);

	<T extends OAuth2AuthorizationGrantAuthorization> T findByAccessToken_TokenValue(String token);

	<T extends OAuth2AuthorizationGrantAuthorization> T findByRefreshToken_TokenValue(String token);

	<T extends OidcAuthorizationCodeGrantAuthorization> T findByIdToken_TokenValue(String token);

	<T extends OAuth2DeviceCodeGrantAuthorization> T findByDeviceState(String token);

	<T extends OAuth2DeviceCodeGrantAuthorization> T findByDeviceCode_TokenValue(String token);

	<T extends OAuth2DeviceCodeGrantAuthorization> T findByUserCode_TokenValue(String token);

	<T extends OAuth2AuthorizationGrantAuthorization> T findByStateOrAuthorizationCode_TokenValueOrAccessToken_TokenValueOrRefreshToken_TokenValueOrIdToken_TokenValueOrDeviceStateOrDeviceCode_TokenValueOrUserCode_TokenValue(
			String state, String authorizationCode, String accessToken, String refreshToken, String idToken,
			String deviceState, String deviceCode, String userCode);

}
