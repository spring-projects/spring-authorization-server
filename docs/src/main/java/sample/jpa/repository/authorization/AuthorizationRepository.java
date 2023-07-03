/*
 * Copyright 2022-2023 the original author or authors.
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
package sample.jpa.repository.authorization;

import java.util.Optional;

import sample.jpa.entity.authorization.Authorization;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorizationRepository extends JpaRepository<Authorization, String> {
	Optional<Authorization> findByState(String state);
	Optional<Authorization> findByAuthorizationCodeValue(String authorizationCode);
	Optional<Authorization> findByAccessTokenValue(String accessToken);
	Optional<Authorization> findByRefreshTokenValue(String refreshToken);
	Optional<Authorization> findByOidcIdTokenValue(String idToken);
	Optional<Authorization> findByUserCodeValue(String userCode);
	Optional<Authorization> findByDeviceCodeValue(String deviceCode);
	@Query("select a from Authorization a where a.state = :token" +
			" or a.authorizationCodeValue = :token" +
			" or a.accessTokenValue = :token" +
			" or a.refreshTokenValue = :token" +
			" or a.oidcIdTokenValue = :token" +
			" or a.userCodeValue = :token" +
			" or a.deviceCodeValue = :token"
	)
	Optional<Authorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);
}
