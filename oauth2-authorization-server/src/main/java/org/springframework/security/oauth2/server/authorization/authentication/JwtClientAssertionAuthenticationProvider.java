/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.ProviderSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} implementation used for OAuth 2.0 Client Authentication,
 * which authenticates the (JWT) {@link OAuth2ParameterNames#CLIENT_ASSERTION client_assertion} parameter.
 *
 * @author Rafal Lewczuk
 * @author Joe Grandja
 * @since 0.2.3
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 */
public final class JwtClientAssertionAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";
	private static final ClientAuthenticationMethod JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
	private final RegisteredClientRepository registeredClientRepository;
	private final CodeVerifierAuthenticator codeVerifierAuthenticator;
	private final JwtClientAssertionDecoderFactory jwtClientAssertionDecoderFactory;

	/**
	 * Constructs a {@code JwtClientAssertionAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public JwtClientAssertionAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.codeVerifierAuthenticator = new CodeVerifierAuthenticator(authorizationService);
		this.jwtClientAssertionDecoderFactory = new JwtClientAssertionDecoderFactory();
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		if (!JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return null;
		}

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT) &&
				!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
			throwInvalidClient("authentication_method");
		}

		if (clientAuthentication.getCredentials() == null) {
			throwInvalidClient("credentials");
		}

		Jwt jwtAssertion = null;
		JwtDecoder jwtDecoder = this.jwtClientAssertionDecoderFactory.createDecoder(registeredClient);
		try {
			jwtAssertion = jwtDecoder.decode(clientAuthentication.getCredentials().toString());
		} catch (JwtException ex) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ASSERTION, ex);
		}

		// Validate the "code_verifier" parameter for the confidential client, if available
		this.codeVerifierAuthenticator.authenticateIfAvailable(clientAuthentication, registeredClient);

		ClientAuthenticationMethod clientAuthenticationMethod =
				registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm() instanceof SignatureAlgorithm ?
						ClientAuthenticationMethod.PRIVATE_KEY_JWT :
						ClientAuthenticationMethod.CLIENT_SECRET_JWT;

		return new OAuth2ClientAuthenticationToken(registeredClient, clientAuthenticationMethod, jwtAssertion);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void throwInvalidClient(String parameterName) {
		throwInvalidClient(parameterName, null);
	}

	private static void throwInvalidClient(String parameterName, Throwable cause) {
		OAuth2Error error = new OAuth2Error(
				OAuth2ErrorCodes.INVALID_CLIENT,
				"Client authentication failed: " + parameterName,
				ERROR_URI
		);
		throw new OAuth2AuthenticationException(error, error.toString(), cause);
	}

	private static class JwtClientAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClient> {
		private static final String JWT_CLIENT_AUTHENTICATION_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-3";

		private static final Map<JwsAlgorithm, String> JCA_ALGORITHM_MAPPINGS;

		static {
			Map<JwsAlgorithm, String> mappings = new HashMap<>();
			mappings.put(MacAlgorithm.HS256, "HmacSHA256");
			mappings.put(MacAlgorithm.HS384, "HmacSHA384");
			mappings.put(MacAlgorithm.HS512, "HmacSHA512");
			JCA_ALGORITHM_MAPPINGS = Collections.unmodifiableMap(mappings);
		}

		private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

		@Override
		public JwtDecoder createDecoder(RegisteredClient registeredClient) {
			Assert.notNull(registeredClient, "registeredClient cannot be null");
			return this.jwtDecoders.computeIfAbsent(registeredClient.getId(), (key) -> {
				NimbusJwtDecoder jwtDecoder = buildDecoder(registeredClient);
				jwtDecoder.setJwtValidator(createJwtValidator(registeredClient));
				return jwtDecoder;
			});
		}

		private static NimbusJwtDecoder buildDecoder(RegisteredClient registeredClient) {
			JwsAlgorithm jwsAlgorithm = registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm();
			if (jwsAlgorithm instanceof SignatureAlgorithm) {
				String jwkSetUrl = registeredClient.getClientSettings().getJwkSetUrl();
				if (!StringUtils.hasText(jwkSetUrl)) {
					OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
							"Failed to find a Signature Verifier for Client: '"
									+ registeredClient.getId()
									+ "'. Check to ensure you have configured the JWK Set URL.",
							JWT_CLIENT_AUTHENTICATION_ERROR_URI);
					throw new OAuth2AuthenticationException(oauth2Error);
				}
				return NimbusJwtDecoder.withJwkSetUri(jwkSetUrl).jwsAlgorithm((SignatureAlgorithm) jwsAlgorithm).build();
			}
			if (jwsAlgorithm instanceof MacAlgorithm) {
				String clientSecret = registeredClient.getClientSecret();
				if (!StringUtils.hasText(clientSecret)) {
					OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
							"Failed to find a Signature Verifier for Client: '"
									+ registeredClient.getId()
									+ "'. Check to ensure you have configured the client secret.",
							JWT_CLIENT_AUTHENTICATION_ERROR_URI);
					throw new OAuth2AuthenticationException(oauth2Error);
				}
				SecretKeySpec secretKeySpec = new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8),
						JCA_ALGORITHM_MAPPINGS.get(jwsAlgorithm));
				return NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm((MacAlgorithm) jwsAlgorithm).build();
			}
			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
					"Failed to find a Signature Verifier for Client: '"
							+ registeredClient.getId()
							+ "'. Check to ensure you have configured a valid JWS Algorithm: '" + jwsAlgorithm + "'.",
					JWT_CLIENT_AUTHENTICATION_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error);
		}

		private static OAuth2TokenValidator<Jwt> createJwtValidator(RegisteredClient registeredClient) {
			String clientId = registeredClient.getClientId();
			return new DelegatingOAuth2TokenValidator<>(
					new JwtClaimValidator<>(JwtClaimNames.ISS, clientId::equals),
					new JwtClaimValidator<>(JwtClaimNames.SUB, clientId::equals),
					new JwtClaimValidator<>(JwtClaimNames.AUD, containsProviderAudience()),
					new JwtClaimValidator<>(JwtClaimNames.EXP, Objects::nonNull),
					new JwtTimestampValidator()
			);
		}

		private static Predicate<List<String>> containsProviderAudience() {
			return (audienceClaim) -> {
				if (CollectionUtils.isEmpty(audienceClaim)) {
					return false;
				}
				List<String> providerAudience = getProviderAudience();
				for (String audience : audienceClaim) {
					if (providerAudience.contains(audience)) {
						return true;
					}
				}
				return false;
			};
		}

		private static List<String> getProviderAudience() {
			ProviderContext providerContext = ProviderContextHolder.getProviderContext();
			if (!StringUtils.hasText(providerContext.getIssuer())) {
				return Collections.emptyList();
			}

			ProviderSettings providerSettings = providerContext.getProviderSettings();
			List<String> providerAudience = new ArrayList<>();
			providerAudience.add(providerContext.getIssuer());
			providerAudience.add(asUrl(providerContext.getIssuer(), providerSettings.getTokenEndpoint()));
			providerAudience.add(asUrl(providerContext.getIssuer(), providerSettings.getTokenIntrospectionEndpoint()));
			providerAudience.add(asUrl(providerContext.getIssuer(), providerSettings.getTokenRevocationEndpoint()));
			return providerAudience;
		}

		private static String asUrl(String issuer, String endpoint) {
			return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
		}

	}

}
