/*
 * Copyright 2020 the original author or authors.
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

package org.springframework.security.oauth2.core.introspection.http.converter;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.TOKEN_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.USERNAME;
import static org.springframework.security.oauth2.core.endpoint.OAuth2TokenIntrospectionResponse.ACTIVE;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.AUD;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.JTI;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.NBF;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2TokenIntrospectionResponse;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link HttpMessageConverter} for an {@link OAuth2TokenIntrospectionResponse} Token Introspection Response.
 *
 * @author Gerardo Roza
 * @since 0.1.1
 * @see AbstractHttpMessageConverter
 * @see OAuth2TokenIntrospectionResponse
 */
public class OAuth2TokenIntrospectionResponseHttpMessageConverter
		extends AbstractHttpMessageConverter<OAuth2TokenIntrospectionResponse> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	private Converter<Map<String, Object>, OAuth2TokenIntrospectionResponse> tokenIntrospectionResponseConverter = new OAuth2TokenIntrospectionResponseConverter();
	private Converter<OAuth2TokenIntrospectionResponse, Map<String, Object>> tokenIntrospectionResponseParametersConverter = OAuth2TokenIntrospectionResponse::getParameters;

	public OAuth2TokenIntrospectionResponseHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2TokenIntrospectionResponse.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2TokenIntrospectionResponse readInternal(Class<? extends OAuth2TokenIntrospectionResponse> clazz,
			HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
		try {
			Map<String, Object> tokenIntrospectionResponseParameters = (Map<String, Object>) this.jsonMessageConverter
					.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.tokenIntrospectionResponseConverter.convert(tokenIntrospectionResponseParameters);
		} catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the Token Introspection Response: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2TokenIntrospectionResponse tokenIntrospectionResponse,
			HttpOutputMessage outputMessage) {
		try {

			Map<String, Object> tokenIntrospectionResponseParameters = this.tokenIntrospectionResponseParametersConverter
					.convert(tokenIntrospectionResponse);
			this.jsonMessageConverter.write(
					tokenIntrospectionResponseParameters, STRING_OBJECT_MAP.getType(), MediaType.APPLICATION_JSON,
					outputMessage);
		} catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the Token Introspection Response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the Token Introspection parameters to an
	 * {@link OAuth2TokenIntrospectionResponse}.
	 *
	 * @param tokenIntrospectionResponseConverter the {@link Converter} used for converting to an
	 * {@link OAuth2TokenIntrospectionResponse}
	 */
	public void setTokenIntrospectionResponseConverter(
			Converter<Map<String, Object>, OAuth2TokenIntrospectionResponse> tokenIntrospectionResponseConverter) {
		Assert.notNull(tokenIntrospectionResponseConverter, "tokenIntrospectionResponseConverter cannot be null");
		this.tokenIntrospectionResponseConverter = tokenIntrospectionResponseConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OAuth2TokenIntrospectionResponse} to a {@code Map} representation of
	 * the Token Introspection Response.
	 *
	 * @param tokenIntrospectionResponseParametersConverter the {@link Converter} used for converting to a {@code Map} representation
	 * of the Token Introspection Response
	 */
	public void setTokenIntrospectionResponseParametersConverter(
			Converter<OAuth2TokenIntrospectionResponse, Map<String, Object>> tokenIntrospectionResponseParametersConverter) {
		Assert.notNull(
				tokenIntrospectionResponseParametersConverter,
				"tokenIntrospectionResponseParametersConverter cannot be null");
		this.tokenIntrospectionResponseParametersConverter = tokenIntrospectionResponseParametersConverter;
	}

	private static final class OAuth2TokenIntrospectionResponseConverter
			implements Converter<Map<String, Object>, OAuth2TokenIntrospectionResponse> {
		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService
				.getSharedInstance();
		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);
		private static final TypeDescriptor BOOLEAN_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean.class);
		private static final TypeDescriptor INSTANT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Instant.class);
		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);
		private final ClaimTypeConverter parameterTypeConverter;

		private OAuth2TokenIntrospectionResponseConverter() {
			Converter<Object, ?> collectionStringConverter = getConverter(
					TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
			Converter<Object, ?> booleanConverter = getConverter(BOOLEAN_TYPE_DESCRIPTOR);
			Converter<Object, ?> instantConverter = getConverter(INSTANT_TYPE_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(ACTIVE, booleanConverter);
			claimConverters.put(SCOPE, stringConverter);
			claimConverters.put(CLIENT_ID, stringConverter);
			claimConverters.put(TOKEN_TYPE, stringConverter);
			claimConverters.put(USERNAME, stringConverter);
			claimConverters.put(AUD, collectionStringConverter);
			claimConverters.put(EXP, instantConverter);
			claimConverters.put(IAT, instantConverter);
			claimConverters.put(ISS, stringConverter);
			claimConverters.put(JTI, stringConverter);
			claimConverters.put(NBF, instantConverter);
			claimConverters.put(SUB, stringConverter);
			this.parameterTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OAuth2TokenIntrospectionResponse convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.parameterTypeConverter.convert(source);
			return OAuth2TokenIntrospectionResponse.withClaims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}
	}
}
