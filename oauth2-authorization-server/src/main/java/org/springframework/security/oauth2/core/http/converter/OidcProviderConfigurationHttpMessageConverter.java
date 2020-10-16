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
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.converter.ObjectToSetStringConverter2;
import org.springframework.security.oauth2.core.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.core.oidc.OidcProviderMetadataClaimNames;
import org.springframework.util.Assert;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;


/**
 * A {@link HttpMessageConverter} for an {@link OidcProviderConfiguration OpenID Provider Configuration Metadata}.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see AbstractHttpMessageConverter
 * @see OidcProviderConfiguration
 */
public class OidcProviderConfigurationHttpMessageConverter
		extends AbstractHttpMessageConverter<OidcProviderConfiguration> {
	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP =
			new ParameterizedTypeReference<Map<String, Object>>() {
			};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	private Converter<Map<String, Object>, OidcProviderConfiguration> providerConfigurationConverter = new OidcProviderConfigurationConverter();
	private Converter<OidcProviderConfiguration, Map<String, Object>> providerConfigurationParametersConverter = OidcProviderConfiguration::getClaims;

	public OidcProviderConfigurationHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OidcProviderConfiguration.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OidcProviderConfiguration readInternal(Class<? extends OidcProviderConfiguration> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> providerConfigurationParameters = (Map<String, Object>) this.jsonMessageConverter.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.providerConfigurationConverter.convert(providerConfigurationParameters);
		} catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OpenID Provider Configuration: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OidcProviderConfiguration providerConfiguration, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
		try {
			Map<String, Object> providerConfigurationResponseParameters =
					this.providerConfigurationParametersConverter.convert(providerConfiguration);
			this.jsonMessageConverter.write(
					providerConfigurationResponseParameters,
					STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON,
					outputMessage
			);
		} catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OpenID Provider Configuration: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OidcProviderConfiguration} to a
	 * {@code Map} representation of the OpenID Provider Configuration.
	 *
	 * @param providerConfigurationParametersConverter the {@link Converter} used for converting to a
	 * {@code Map} representation of the OpenID Provider Configuration
	 */
	public final void setProviderConfigurationParametersConverter(
			Converter<OidcProviderConfiguration, Map<String, Object>> providerConfigurationParametersConverter) {
		Assert.notNull(providerConfigurationParametersConverter, "providerConfigurationParametersConverter cannot be null");
		this.providerConfigurationParametersConverter = providerConfigurationParametersConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the OpenID Provider Configuration parameters
	 * to an {@link OidcProviderConfiguration}.
	 *
	 * @param providerConfigurationConverter the {@link Converter} used for converting to an
	 * {@link OidcProviderConfiguration}
	 */
	public final void setProviderConfigurationConverter(Converter<Map<String, Object>, OidcProviderConfiguration> providerConfigurationConverter) {
		Assert.notNull(providerConfigurationConverter, "providerConfigurationConverter cannot be null");
		this.providerConfigurationConverter = providerConfigurationConverter;
	}

	private static final class OidcProviderConfigurationConverter implements Converter<Map<String, Object>, OidcProviderConfiguration> {
		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService.getSharedInstance();
		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);
		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);
		private static final TypeDescriptor URL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(URL.class);
		private final ClaimTypeConverter claimTypeConverter;

		OidcProviderConfigurationConverter() {
			CLAIM_CONVERSION_SERVICE.addConverter(new ObjectToSetStringConverter2());
			Map<String, Converter<Object, ?>> claimNameToConverter = new HashMap<>();
			Converter<Object, ?> setStringConverter = getConverter(TypeDescriptor.collection(Set.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

			claimNameToConverter.put(OidcProviderMetadataClaimNames.ISSUER, urlConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.AUTHORIZATION_ENDPOINT, urlConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT, urlConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.JWKS_URI, urlConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.GRANT_TYPES_SUPPORTED, setStringConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, setStringConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED, setStringConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.SCOPES_SUPPORTED, setStringConverter);
			claimNameToConverter.put(OidcProviderMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, setStringConverter);
			this.claimTypeConverter = new ClaimTypeConverter(claimNameToConverter);
		}

		@Override
		public OidcProviderConfiguration convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return OidcProviderConfiguration.withClaims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}
	}
}
