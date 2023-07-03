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
package sample.jpa.service.authorization;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import sample.jpa.entity.authorization.Authorization;
import sample.jpa.repository.authorization.AuthorizationRepository;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Component
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {
	private final AuthorizationRepository authorizationRepository;
	private final RegisteredClientRepository registeredClientRepository;
	private final ObjectMapper objectMapper = new ObjectMapper();

	public JpaOAuth2AuthorizationService(AuthorizationRepository authorizationRepository, RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(authorizationRepository, "authorizationRepository cannot be null");
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.authorizationRepository = authorizationRepository;
		this.registeredClientRepository = registeredClientRepository;

		ClassLoader classLoader = JpaOAuth2AuthorizationService.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		this.objectMapper.registerModules(securityModules);
		this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		this.authorizationRepository.save(toEntity(authorization));
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		this.authorizationRepository.deleteById(authorization.getId());
	}

	@Override
	public OAuth2Authorization findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.authorizationRepository.findById(id).map(this::toObject).orElse(null);
	}

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");

		Optional<Authorization> result;
		if (tokenType == null) {
			result = this.authorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(token);
		} else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			result = this.authorizationRepository.findByState(token);
		} else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			result = this.authorizationRepository.findByAuthorizationCodeValue(token);
		} else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
			result = this.authorizationRepository.findByAccessTokenValue(token);
		} else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
			result = this.authorizationRepository.findByRefreshTokenValue(token);
		} else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
			result = this.authorizationRepository.findByOidcIdTokenValue(token);
		} else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
			result = this.authorizationRepository.findByUserCodeValue(token);
		} else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
			result = this.authorizationRepository.findByDeviceCodeValue(token);
		} else {
			result = Optional.empty();
		}

		return result.map(this::toObject).orElse(null);
	}

	private OAuth2Authorization toObject(Authorization entity) {
		RegisteredClient registeredClient = this.registeredClientRepository.findById(entity.getRegisteredClientId());
		if (registeredClient == null) {
			throw new DataRetrievalFailureException(
					"The RegisteredClient with id '" + entity.getRegisteredClientId() + "' was not found in the RegisteredClientRepository.");
		}

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.id(entity.getId())
				.principalName(entity.getPrincipalName())
				.authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
				.authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
				.attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));
		if (entity.getState() != null) {
			builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
		}

		if (entity.getAuthorizationCodeValue() != null) {
			OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
					entity.getAuthorizationCodeValue(),
					entity.getAuthorizationCodeIssuedAt(),
					entity.getAuthorizationCodeExpiresAt());
			builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
		}

		if (entity.getAccessTokenValue() != null) {
			OAuth2AccessToken accessToken = new OAuth2AccessToken(
					OAuth2AccessToken.TokenType.BEARER,
					entity.getAccessTokenValue(),
					entity.getAccessTokenIssuedAt(),
					entity.getAccessTokenExpiresAt(),
					StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
			builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
		}

		if (entity.getRefreshTokenValue() != null) {
			OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
					entity.getRefreshTokenValue(),
					entity.getRefreshTokenIssuedAt(),
					entity.getRefreshTokenExpiresAt());
			builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
		}

		if (entity.getOidcIdTokenValue() != null) {
			OidcIdToken idToken = new OidcIdToken(
					entity.getOidcIdTokenValue(),
					entity.getOidcIdTokenIssuedAt(),
					entity.getOidcIdTokenExpiresAt(),
					parseMap(entity.getOidcIdTokenClaims()));
			builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
		}

		if (entity.getUserCodeValue() != null) {
			OAuth2UserCode userCode = new OAuth2UserCode(
					entity.getUserCodeValue(),
					entity.getUserCodeIssuedAt(),
					entity.getUserCodeExpiresAt());
			builder.token(userCode, metadata -> metadata.putAll(parseMap(entity.getUserCodeMetadata())));
		}

		if (entity.getDeviceCodeValue() != null) {
			OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
					entity.getDeviceCodeValue(),
					entity.getDeviceCodeIssuedAt(),
					entity.getDeviceCodeExpiresAt());
			builder.token(deviceCode, metadata -> metadata.putAll(parseMap(entity.getDeviceCodeMetadata())));
		}

		return builder.build();
	}

	private Authorization toEntity(OAuth2Authorization authorization) {
		Authorization entity = new Authorization();
		entity.setId(authorization.getId());
		entity.setRegisteredClientId(authorization.getRegisteredClientId());
		entity.setPrincipalName(authorization.getPrincipalName());
		entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
		entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ","));
		entity.setAttributes(writeMap(authorization.getAttributes()));
		entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
				authorization.getToken(OAuth2AuthorizationCode.class);
		setTokenValues(
				authorizationCode,
				entity::setAuthorizationCodeValue,
				entity::setAuthorizationCodeIssuedAt,
				entity::setAuthorizationCodeExpiresAt,
				entity::setAuthorizationCodeMetadata
		);

		OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
				authorization.getToken(OAuth2AccessToken.class);
		setTokenValues(
				accessToken,
				entity::setAccessTokenValue,
				entity::setAccessTokenIssuedAt,
				entity::setAccessTokenExpiresAt,
				entity::setAccessTokenMetadata
		);
		if (accessToken != null && accessToken.getToken().getScopes() != null) {
			entity.setAccessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
				authorization.getToken(OAuth2RefreshToken.class);
		setTokenValues(
				refreshToken,
				entity::setRefreshTokenValue,
				entity::setRefreshTokenIssuedAt,
				entity::setRefreshTokenExpiresAt,
				entity::setRefreshTokenMetadata
		);

		OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
				authorization.getToken(OidcIdToken.class);
		setTokenValues(
				oidcIdToken,
				entity::setOidcIdTokenValue,
				entity::setOidcIdTokenIssuedAt,
				entity::setOidcIdTokenExpiresAt,
				entity::setOidcIdTokenMetadata
		);
		if (oidcIdToken != null) {
			entity.setOidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
		}

		OAuth2Authorization.Token<OAuth2UserCode> userCode =
				authorization.getToken(OAuth2UserCode.class);
		setTokenValues(
				userCode,
				entity::setUserCodeValue,
				entity::setUserCodeIssuedAt,
				entity::setUserCodeExpiresAt,
				entity::setUserCodeMetadata
		);

		OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
				authorization.getToken(OAuth2DeviceCode.class);
		setTokenValues(
				deviceCode,
				entity::setDeviceCodeValue,
				entity::setDeviceCodeIssuedAt,
				entity::setDeviceCodeExpiresAt,
				entity::setDeviceCodeMetadata
		);

		return entity;
	}

	private void setTokenValues(
			OAuth2Authorization.Token<?> token,
			Consumer<String> tokenValueConsumer,
			Consumer<Instant> issuedAtConsumer,
			Consumer<Instant> expiresAtConsumer,
			Consumer<String> metadataConsumer) {
		if (token != null) {
			OAuth2Token oAuth2Token = token.getToken();
			tokenValueConsumer.accept(oAuth2Token.getTokenValue());
			issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
			expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
			metadataConsumer.accept(writeMap(token.getMetadata()));
		}
	}

	private Map<String, Object> parseMap(String data) {
		try {
			return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
			});
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	private String writeMap(Map<String, Object> metadata) {
		try {
			return this.objectMapper.writeValueAsString(metadata);
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.AUTHORIZATION_CODE;
		} else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.CLIENT_CREDENTIALS;
		} else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.REFRESH_TOKEN;
		} else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.DEVICE_CODE;
		}
		return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
	}
}
