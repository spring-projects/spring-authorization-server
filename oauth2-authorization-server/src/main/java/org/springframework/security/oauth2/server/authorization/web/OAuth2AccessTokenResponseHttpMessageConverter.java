/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.web;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.MapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponseMapConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * TODO
 * This class is a copy from Spring Security and should be removed after upgrading to Spring Security 5.6.0 GA.
 *
 * A {@link HttpMessageConverter} for an {@link OAuth2AccessTokenResponse OAuth 2.0 Access
 * Token Response}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see AbstractHttpMessageConverter
 * @see OAuth2AccessTokenResponse
 */
class OAuth2AccessTokenResponseHttpMessageConverter
		extends AbstractHttpMessageConverter<OAuth2AccessTokenResponse> {

	private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	/**
	 * @deprecated This field should no longer be used
	 */
	@Deprecated
	protected Converter<Map<String, String>, OAuth2AccessTokenResponse> tokenResponseConverter = new MapOAuth2AccessTokenResponseConverter();

	private Converter<Map<String, ?>, OAuth2AccessTokenResponse> accessTokenResponseConverter = new DefaultMapOAuth2AccessTokenResponseConverter();

	/**
	 * @deprecated This field should no longer be used
	 */
	@Deprecated
	protected Converter<OAuth2AccessTokenResponse, Map<String, String>> tokenResponseParametersConverter = new OAuth2AccessTokenResponseMapConverter();

	private Converter<OAuth2AccessTokenResponse, Map<String, Object>> accessTokenResponseParametersConverter = new DefaultOAuth2AccessTokenResponseMapConverter();

	OAuth2AccessTokenResponseHttpMessageConverter() {
		super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2AccessTokenResponse.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2AccessTokenResponse readInternal(Class<? extends OAuth2AccessTokenResponse> clazz,
			HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
		try {
			Map<String, Object> tokenResponseParameters = (Map<String, Object>) this.jsonMessageConverter
					.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			// Only use deprecated converter if it has been set directly
			if (this.tokenResponseConverter.getClass() != MapOAuth2AccessTokenResponseConverter.class) {
				// gh-6463: Parse parameter values as Object in order to handle potential
				// JSON Object and then convert values to String
				Map<String, String> stringTokenResponseParameters = new HashMap<>();
				tokenResponseParameters
						.forEach((key, value) -> stringTokenResponseParameters.put(key, String.valueOf(value)));
				return this.tokenResponseConverter.convert(stringTokenResponseParameters);
			}
			return this.accessTokenResponseConverter.convert(tokenResponseParameters);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OAuth 2.0 Access Token Response: " + ex.getMessage(), ex,
					inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2AccessTokenResponse tokenResponse, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> tokenResponseParameters;
			// Only use deprecated converter if it has been set directly
			if (this.tokenResponseParametersConverter.getClass() != OAuth2AccessTokenResponseMapConverter.class) {
				tokenResponseParameters = new LinkedHashMap<>(
						this.tokenResponseParametersConverter.convert(tokenResponse));
			}
			else {
				tokenResponseParameters = this.accessTokenResponseParametersConverter.convert(tokenResponse);
			}
			this.jsonMessageConverter.write(tokenResponseParameters, STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OAuth 2.0 Access Token Response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 Access Token Response
	 * parameters to an {@link OAuth2AccessTokenResponse}.
	 * @deprecated Use {@link #setAccessTokenResponseConverter(Converter)} instead
	 * @param tokenResponseConverter the {@link Converter} used for converting to an
	 * {@link OAuth2AccessTokenResponse}
	 */
	@Deprecated
	public final void setTokenResponseConverter(
			Converter<Map<String, String>, OAuth2AccessTokenResponse> tokenResponseConverter) {
		Assert.notNull(tokenResponseConverter, "tokenResponseConverter cannot be null");
		this.tokenResponseConverter = tokenResponseConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 Access Token Response
	 * parameters to an {@link OAuth2AccessTokenResponse}.
	 * @param accessTokenResponseConverter the {@link Converter} used for converting to an
	 * {@link OAuth2AccessTokenResponse}
	 * @since 5.6
	 */
	public final void setAccessTokenResponseConverter(
			Converter<Map<String, ?>, OAuth2AccessTokenResponse> accessTokenResponseConverter) {
		Assert.notNull(accessTokenResponseConverter, "accessTokenResponseConverter cannot be null");
		this.accessTokenResponseConverter = accessTokenResponseConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link OAuth2AccessTokenResponse} to a {@code Map} representation of the OAuth 2.0
	 * Access Token Response parameters.
	 * @deprecated Use {@link #setAccessTokenResponseParametersConverter(Converter)}
	 * instead
	 * @param tokenResponseParametersConverter the {@link Converter} used for converting
	 * to a {@code Map} representation of the Access Token Response parameters
	 */
	@Deprecated
	public final void setTokenResponseParametersConverter(
			Converter<OAuth2AccessTokenResponse, Map<String, String>> tokenResponseParametersConverter) {
		Assert.notNull(tokenResponseParametersConverter, "tokenResponseParametersConverter cannot be null");
		this.tokenResponseParametersConverter = tokenResponseParametersConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link OAuth2AccessTokenResponse} to a {@code Map} representation of the OAuth 2.0
	 * Access Token Response parameters.
	 * @param accessTokenResponseParametersConverter the {@link Converter} used for
	 * converting to a {@code Map} representation of the Access Token Response parameters
	 * @since 5.6
	 */
	public final void setAccessTokenResponseParametersConverter(
			Converter<OAuth2AccessTokenResponse, Map<String, Object>> accessTokenResponseParametersConverter) {
		Assert.notNull(accessTokenResponseParametersConverter, "accessTokenResponseParametersConverter cannot be null");
		this.accessTokenResponseParametersConverter = accessTokenResponseParametersConverter;
	}

	/**
	 * Utility methods for {@link HttpMessageConverter}'s.
	 *
	 * @author Joe Grandja
	 * @since 5.1
	 */
	static final class HttpMessageConverters {

		private static final boolean jackson2Present;

		private static final boolean gsonPresent;

		private static final boolean jsonbPresent;

		static {
			ClassLoader classLoader = HttpMessageConverters.class.getClassLoader();
			jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader)
					&& ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);
			gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);
			jsonbPresent = ClassUtils.isPresent("javax.json.bind.Jsonb", classLoader);
		}

		private HttpMessageConverters() {
		}

		static GenericHttpMessageConverter<Object> getJsonMessageConverter() {
			if (jackson2Present) {
				return new MappingJackson2HttpMessageConverter();
			}
			if (gsonPresent) {
				return new GsonHttpMessageConverter();
			}
			if (jsonbPresent) {
				return new JsonbHttpMessageConverter();
			}
			return null;
		}

	}

	/**
	 * A {@link Converter} that converts the provided OAuth 2.0 Access Token Response
	 * parameters to an {@link OAuth2AccessTokenResponse}.
	 *
	 * @author Steve Riesenberg
	 * @since 5.6
	 */
	static final class DefaultMapOAuth2AccessTokenResponseConverter
			implements Converter<Map<String, ?>, OAuth2AccessTokenResponse> {

		private static final Set<String> TOKEN_RESPONSE_PARAMETER_NAMES = new HashSet<>(
				Arrays.asList(OAuth2ParameterNames.ACCESS_TOKEN, OAuth2ParameterNames.EXPIRES_IN,
						OAuth2ParameterNames.REFRESH_TOKEN, OAuth2ParameterNames.SCOPE, OAuth2ParameterNames.TOKEN_TYPE));

		@Override
		public OAuth2AccessTokenResponse convert(Map<String, ?> source) {
			String accessToken = getParameterValue(source, OAuth2ParameterNames.ACCESS_TOKEN);
			OAuth2AccessToken.TokenType accessTokenType = getAccessTokenType(source);
			long expiresIn = getExpiresIn(source);
			Set<String> scopes = getScopes(source);
			String refreshToken = getParameterValue(source, OAuth2ParameterNames.REFRESH_TOKEN);
			Map<String, Object> additionalParameters = new LinkedHashMap<>();
			for (Map.Entry<String, ?> entry : source.entrySet()) {
				if (!TOKEN_RESPONSE_PARAMETER_NAMES.contains(entry.getKey())) {
					additionalParameters.put(entry.getKey(), entry.getValue());
				}
			}
			// @formatter:off
			return OAuth2AccessTokenResponse.withToken(accessToken)
					.tokenType(accessTokenType)
					.expiresIn(expiresIn)
					.scopes(scopes)
					.refreshToken(refreshToken)
					.additionalParameters(additionalParameters)
					.build();
			// @formatter:on
		}

		private static OAuth2AccessToken.TokenType getAccessTokenType(Map<String, ?> tokenResponseParameters) {
			if (OAuth2AccessToken.TokenType.BEARER.getValue()
					.equalsIgnoreCase(getParameterValue(tokenResponseParameters, OAuth2ParameterNames.TOKEN_TYPE))) {
				return OAuth2AccessToken.TokenType.BEARER;
			}
			return null;
		}

		private static long getExpiresIn(Map<String, ?> tokenResponseParameters) {
			return getParameterValue(tokenResponseParameters, OAuth2ParameterNames.EXPIRES_IN, 0L);
		}

		private static Set<String> getScopes(Map<String, ?> tokenResponseParameters) {
			if (tokenResponseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
				String scope = getParameterValue(tokenResponseParameters, OAuth2ParameterNames.SCOPE);
				return new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
			}
			return Collections.emptySet();
		}

		private static String getParameterValue(Map<String, ?> tokenResponseParameters, String parameterName) {
			Object obj = tokenResponseParameters.get(parameterName);
			return (obj != null) ? obj.toString() : null;
		}

		private static long getParameterValue(Map<String, ?> tokenResponseParameters, String parameterName,
				long defaultValue) {
			long parameterValue = defaultValue;

			Object obj = tokenResponseParameters.get(parameterName);
			if (obj != null) {
				// Final classes Long and Integer do not need to be coerced
				if (obj.getClass() == Long.class) {
					parameterValue = (Long) obj;
				}
				else if (obj.getClass() == Integer.class) {
					parameterValue = (Integer) obj;
				}
				else {
					// Attempt to coerce to a long (typically from a String)
					try {
						parameterValue = Long.parseLong(obj.toString());
					}
					catch (NumberFormatException ignored) {
					}
				}
			}

			return parameterValue;
		}

	}

	/**
	 * A {@link Converter} that converts the provided {@link OAuth2AccessTokenResponse} to a
	 * {@code Map} representation of the OAuth 2.0 Access Token Response parameters.
	 *
	 * @author Steve Riesenberg
	 * @since 5.6
	 */
	static final class DefaultOAuth2AccessTokenResponseMapConverter
			implements Converter<OAuth2AccessTokenResponse, Map<String, Object>> {

		@Override
		public Map<String, Object> convert(OAuth2AccessTokenResponse tokenResponse) {
			Map<String, Object> parameters = new HashMap<>();
			parameters.put(OAuth2ParameterNames.ACCESS_TOKEN, tokenResponse.getAccessToken().getTokenValue());
			parameters.put(OAuth2ParameterNames.TOKEN_TYPE, tokenResponse.getAccessToken().getTokenType().getValue());
			parameters.put(OAuth2ParameterNames.EXPIRES_IN, getExpiresIn(tokenResponse));
			if (!CollectionUtils.isEmpty(tokenResponse.getAccessToken().getScopes())) {
				parameters.put(OAuth2ParameterNames.SCOPE,
						StringUtils.collectionToDelimitedString(tokenResponse.getAccessToken().getScopes(), " "));
			}
			if (tokenResponse.getRefreshToken() != null) {
				parameters.put(OAuth2ParameterNames.REFRESH_TOKEN, tokenResponse.getRefreshToken().getTokenValue());
			}
			if (!CollectionUtils.isEmpty(tokenResponse.getAdditionalParameters())) {
				for (Map.Entry<String, Object> entry : tokenResponse.getAdditionalParameters().entrySet()) {
					parameters.put(entry.getKey(), entry.getValue());
				}
			}
			return parameters;
		}

		private static long getExpiresIn(OAuth2AccessTokenResponse tokenResponse) {
			if (tokenResponse.getAccessToken().getExpiresAt() != null) {
				return ChronoUnit.SECONDS.between(Instant.now(), tokenResponse.getAccessToken().getExpiresAt());
			}
			return -1;
		}

	}

}
