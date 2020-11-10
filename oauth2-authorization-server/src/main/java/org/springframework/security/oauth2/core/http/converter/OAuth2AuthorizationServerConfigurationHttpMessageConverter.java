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
package org.springframework.security.oauth2.core.http.converter;

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
import org.springframework.security.oauth2.core.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationServerConfiguration;
import org.springframework.util.Assert;

import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;


/**
 * A {@link HttpMessageConverter} for an {@link OAuth2AuthorizationServerConfiguration OAuth 2.0 Authorization Server Configuration Response}.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.1
 * @see AbstractHttpMessageConverter
 * @see OAuth2AuthorizationServerConfiguration
 */
public class OAuth2AuthorizationServerConfigurationHttpMessageConverter
		extends AbstractHttpMessageConverter<OAuth2AuthorizationServerConfiguration> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP =
			new ParameterizedTypeReference<Map<String, Object>>() {};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	private Converter<Map<String, Object>, OAuth2AuthorizationServerConfiguration> authorizationServerConfigurationConverter = new OAuth2AuthorizationServerConfigurationConverter();
	private Converter<OAuth2AuthorizationServerConfiguration, Map<String, Object>> authorizationServerConfigurationParametersConverter = OAuth2AuthorizationServerConfiguration::getClaims;

	public OAuth2AuthorizationServerConfigurationHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2AuthorizationServerConfiguration.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2AuthorizationServerConfiguration readInternal(Class<? extends OAuth2AuthorizationServerConfiguration> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> serverConfigurationParameters =
					(Map<String, Object>) this.jsonMessageConverter.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.authorizationServerConfigurationConverter.convert(serverConfigurationParameters);
		} catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OAuth 2.0 Authorization Server Configuration: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2AuthorizationServerConfiguration providerConfiguration, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> providerConfigurationResponseParameters =
					this.authorizationServerConfigurationParametersConverter.convert(providerConfiguration);
			this.jsonMessageConverter.write(
					providerConfigurationResponseParameters,
					STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON,
					outputMessage
			);
		} catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OAuth 2.0 Authorization Server Configuration: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 Authorization Server Configuration
	 * parameters to an {@link OAuth2AuthorizationServerConfiguration}.
	 *
	 * @param authorizationServerConfigurationConverter the {@link Converter} used for converting to
	 * an {@link OAuth2AuthorizationServerConfiguration}.
	 */
	public void setAuthorizationServerConfigurationConverter(Converter<Map<String, Object>, OAuth2AuthorizationServerConfiguration> authorizationServerConfigurationConverter) {
		Assert.notNull(authorizationServerConfigurationConverter, "authorizationServerConfigurationConverter cannot be null");
		this.authorizationServerConfigurationConverter = authorizationServerConfigurationConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OAuth2AuthorizationServerConfiguration} to a
	 * {@code Map} representation of the OAuth 2.0 Authorization Server Configuration.
	 *
	 * @param authorizationServerConfigurationParametersConverter the {@link Converter} used for converting to a
	 * {@code Map} representation of the OAuth 2.0 Authorization Server Configuration.
	 */
	public void setAuthorizationServerConfigurationParametersConverter(Converter<OAuth2AuthorizationServerConfiguration, Map<String, Object>> authorizationServerConfigurationParametersConverter) {
		Assert.notNull(authorizationServerConfigurationParametersConverter, "authorizationServerConfigurationParametersConverter cannot be null");
		this.authorizationServerConfigurationParametersConverter = authorizationServerConfigurationParametersConverter;
	}

	private static final class OAuth2AuthorizationServerConfigurationConverter implements Converter<Map<String, Object>, OAuth2AuthorizationServerConfiguration> {
		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService.getSharedInstance();
		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);
		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);
		private static final TypeDescriptor URL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(URL.class);
		private final ClaimTypeConverter claimTypeConverter;

		private OAuth2AuthorizationServerConfigurationConverter() {
			Map<String, Converter<Object, ?>> claimNameToConverter = new HashMap<>();
			Converter<Object, ?> collectionStringConverter = getConverter(
					TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, urlConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, urlConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, urlConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, urlConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, urlConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, collectionStringConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, collectionStringConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, collectionStringConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, collectionStringConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, collectionStringConverter);
			claimNameToConverter.put(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED, collectionStringConverter);
			this.claimTypeConverter = new ClaimTypeConverter(claimNameToConverter);
		}

		@Override
		public OAuth2AuthorizationServerConfiguration convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return OAuth2AuthorizationServerConfiguration.withClaims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}
	}
}
