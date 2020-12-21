/*
 * Copyright 2020-2021 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc.http.converter;

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
import org.springframework.security.oauth2.core.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link HttpMessageConverter} for an {@link OidcClientRegistration OpenID Client Registration Response}.
 *
 * @author Ovidiu Popa
 * @see AbstractHttpMessageConverter
 * @see OidcClientRegistration
 * @since 0.1.1
 */
public class OidcClientRegistrationHttpMessageConverter extends AbstractHttpMessageConverter<OidcClientRegistration> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP =
			new ParameterizedTypeReference<Map<String, Object>>() {
			};

	private Converter<Map<String, Object>, OidcClientRegistration> clientRegistrationConverter =
			new OidcClientRegistrationConverter();

	private Converter<OidcClientRegistration, Map<String, Object>> clientRegistrationParametersConverter = OidcClientRegistration::getClaims;
	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	public OidcClientRegistrationHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OidcClientRegistration.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OidcClientRegistration readInternal(Class<? extends OidcClientRegistration> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> clientRegistrationParameters =
					(Map<String, Object>) this.jsonMessageConverter.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.clientRegistrationConverter.convert(clientRegistrationParameters);
		} catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OpenID Client Registration Request: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OidcClientRegistration oidcClientRegistration, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {

		try {
			Map<String, Object> claims = clientRegistrationParametersConverter.convert(oidcClientRegistration);
			this.jsonMessageConverter.write(
					claims,
					STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON,
					outputMessage
			);
		} catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OpenID Client Registration response: " + ex.getMessage(), ex);
		}

	}

	/**
	 * Sets the {@link Converter} used for converting the OpenID Client Registration parameters
	 * to an {@link OidcClientRegistration}.
	 *
	 * @param clientRegistrationConverter the {@link Converter} used for converting to an
	 *                                        {@link OidcClientRegistration}
	 */
	public void setClientRegistrationConverter(Converter<Map<String, Object>, OidcClientRegistration> clientRegistrationConverter) {
		Assert.notNull(clientRegistrationConverter, "clientRegistrationConverter cannot be null");
		this.clientRegistrationConverter = clientRegistrationConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OidcClientRegistration} to a
	 * {@code Map} representation of the OpenID Client Registration Response.
	 *
	 * @param clientRegistrationParametersConverter the {@link Converter} used for converting to a
	 *                                         {@code Map} representation of the OpenID Client Registration Response
	 */
	public final void setClientRegistrationParametersConverter(
			Converter<OidcClientRegistration, Map<String, Object>> clientRegistrationParametersConverter) {
		Assert.notNull(clientRegistrationParametersConverter, "clientRegistrationParametersConverter cannot be null");
		this.clientRegistrationParametersConverter = clientRegistrationParametersConverter;
	}

	private static final class OidcClientRegistrationConverter implements Converter<Map<String, Object>, OidcClientRegistration> {
		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService.getSharedInstance();
		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);
		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);
		private final ClaimTypeConverter claimTypeConverter;

		private OidcClientRegistrationConverter() {
			Converter<Object, ?> collectionStringConverter = getConverter(
					TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(OidcClientMetadataClaimNames.REDIRECT_URIS, collectionStringConverter);
			claimConverters.put(OidcClientMetadataClaimNames.RESPONSE_TYPES, collectionStringConverter);
			claimConverters.put(OidcClientMetadataClaimNames.GRANT_TYPES, collectionStringConverter);
			claimConverters.put(OidcClientMetadataClaimNames.CLIENT_NAME, stringConverter);
			claimConverters.put(OidcClientMetadataClaimNames.SCOPE, stringConverter);
			claimConverters.put(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, stringConverter);
			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OidcClientRegistration convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return OidcClientRegistration.withClaims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return source -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}
	}
}
