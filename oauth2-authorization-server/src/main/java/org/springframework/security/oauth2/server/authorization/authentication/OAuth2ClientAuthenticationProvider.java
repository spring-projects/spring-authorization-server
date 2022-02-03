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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
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
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} implementation used for authenticating an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @author Daniel Garnier-Moiroux
 * @author Rafal Lewczuk
 * @since 0.0.1
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see PasswordEncoder
 */
public final class OAuth2ClientAuthenticationProvider implements AuthenticationProvider {
	private static final String CLIENT_AUTHENTICATION_ERROR_URI = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-3.2.1";
	private static final ClientAuthenticationMethod JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private final JwtClientAssertionDecoderFactory jwtClientAssertionDecoderFactory;
	private PasswordEncoder passwordEncoder;

	/**
	 * Constructs an {@code OAuth2ClientAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public OAuth2ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
		this.jwtClientAssertionDecoderFactory = new JwtClientAssertionDecoderFactory();
		this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	/**
	 * Sets the {@link PasswordEncoder} used to validate
	 * the {@link RegisteredClient#getClientSecret() client secret}.
	 * If not set, the client secret will be compared using
	 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.
	 *
	 * @param passwordEncoder the {@link PasswordEncoder} used to validate the client secret
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	@Autowired
	protected void setProviderSettings(ProviderSettings providerSettings) {
		this.jwtClientAssertionDecoderFactory.setProviderSettings(providerSettings);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		return JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod()) ?
				authenticateJwtClientAssertion(authentication) :
				authenticateClientCredentials(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private Authentication authenticateClientCredentials(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(
				clientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient("authentication_method");
		}

		boolean credentialsAuthenticated = false;

		if (clientAuthentication.getCredentials() != null) {
			String clientSecret = clientAuthentication.getCredentials().toString();
			if (!this.passwordEncoder.matches(clientSecret, registeredClient.getClientSecret())) {
				throwInvalidClient(OAuth2ParameterNames.CLIENT_SECRET);
			}
			credentialsAuthenticated = true;
		}

		boolean pkceAuthenticated = authenticatePkceIfAvailable(clientAuthentication, registeredClient);
		credentialsAuthenticated = credentialsAuthenticated || pkceAuthenticated;
		if (!credentialsAuthenticated) {
			throwInvalidClient("credentials");
		}

		return new OAuth2ClientAuthenticationToken(registeredClient,
				clientAuthentication.getClientAuthenticationMethod(), clientAuthentication.getCredentials());
	}

	private Authentication authenticateJwtClientAssertion(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT) &&
				!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
			throwInvalidClient("authentication_method");
		}

		boolean credentialsAuthenticated = false;

		Jwt jwtAssertion = null;
		JwtDecoder jwtDecoder = this.jwtClientAssertionDecoderFactory.createDecoder(registeredClient);
		try {
			jwtAssertion = jwtDecoder.decode(clientAuthentication.getCredentials().toString());
			credentialsAuthenticated = true;
		} catch (JwtException ex) {
			throwInvalidClient(OAuth2ParameterNames.CLIENT_ASSERTION, ex);
		}

		boolean pkceAuthenticated = authenticatePkceIfAvailable(clientAuthentication, registeredClient);
		credentialsAuthenticated = credentialsAuthenticated || pkceAuthenticated;
		if (!credentialsAuthenticated) {
			throwInvalidClient("credentials");
		}

		ClientAuthenticationMethod clientAuthenticationMethod =
				registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm() instanceof SignatureAlgorithm ?
						ClientAuthenticationMethod.PRIVATE_KEY_JWT :
						ClientAuthenticationMethod.CLIENT_SECRET_JWT;

		return new OAuth2ClientAuthenticationToken(registeredClient, clientAuthenticationMethod, jwtAssertion);
	}

	private boolean authenticatePkceIfAvailable(OAuth2ClientAuthenticationToken clientAuthentication,
			RegisteredClient registeredClient) {

		Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
		if (!authorizationCodeGrant(parameters)) {
			return false;
		}

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				(String) parameters.get(OAuth2ParameterNames.CODE),
				AUTHORIZATION_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throwInvalidGrant(OAuth2ParameterNames.CODE);
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationRequest.class.getName());

		String codeChallenge = (String) authorizationRequest.getAdditionalParameters()
				.get(PkceParameterNames.CODE_CHALLENGE);
		if (!StringUtils.hasText(codeChallenge)) {
			if (registeredClient.getClientSettings().isRequireProofKey()) {
				throwInvalidGrant(PkceParameterNames.CODE_CHALLENGE);
			} else {
				return false;
			}
		}

		String codeChallengeMethod = (String) authorizationRequest.getAdditionalParameters()
				.get(PkceParameterNames.CODE_CHALLENGE_METHOD);
		String codeVerifier = (String) parameters.get(PkceParameterNames.CODE_VERIFIER);
		if (!codeVerifierValid(codeVerifier, codeChallenge, codeChallengeMethod)) {
			throwInvalidGrant(PkceParameterNames.CODE_VERIFIER);
		}

		return true;
	}

	private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
		return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
				parameters.get(OAuth2ParameterNames.GRANT_TYPE)) &&
				parameters.get(OAuth2ParameterNames.CODE) != null;
	}

	private static boolean codeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
		if (!StringUtils.hasText(codeVerifier)) {
			return false;
		} else if (!StringUtils.hasText(codeChallengeMethod) || "plain".equals(codeChallengeMethod)) {
			return codeVerifier.equals(codeChallenge);
		} else if ("S256".equals(codeChallengeMethod)) {
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
				String encodedVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
				return encodedVerifier.equals(codeChallenge);
			} catch (NoSuchAlgorithmException ex) {
				// It is unlikely that SHA-256 is not available on the server. If it is not available,
				// there will likely be bigger issues as well. We default to SERVER_ERROR.
			}
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
	}

	private static void throwInvalidClient(String parameterName) {
		throwInvalidClient(parameterName, null);
	}

	private static void throwInvalidClient(String parameterName, Throwable cause) {
		OAuth2Error error = new OAuth2Error(
				OAuth2ErrorCodes.INVALID_CLIENT,
				"Client authentication failed: " + parameterName,
				CLIENT_AUTHENTICATION_ERROR_URI);
		throw new OAuth2AuthenticationException(error, error.toString(), cause);
	}

	private static void throwInvalidGrant(String parameterName) {
		OAuth2Error error = new OAuth2Error(
				OAuth2ErrorCodes.INVALID_GRANT,
				"Client authentication failed: " + parameterName,
				null
		);
		throw new OAuth2AuthenticationException(error);
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
		private List<String> providerAudience = Collections.emptyList();

		private void setProviderSettings(ProviderSettings providerSettings) {
			this.providerAudience = getProviderAudience(providerSettings);
		}

		@Override
		public JwtDecoder createDecoder(RegisteredClient registeredClient) {
			Assert.notNull(registeredClient, "registeredClient cannot be null");
			return this.jwtDecoders.computeIfAbsent(registeredClient.getId(), (key) -> {
				NimbusJwtDecoder jwtDecoder = buildDecoder(registeredClient);
				jwtDecoder.setJwtValidator(createJwtValidator(registeredClient));
				return jwtDecoder;
			});
		}

		private NimbusJwtDecoder buildDecoder(RegisteredClient registeredClient) {
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

		private OAuth2TokenValidator<Jwt> createJwtValidator(RegisteredClient registeredClient) {
			String clientId = registeredClient.getClientId();
			return new DelegatingOAuth2TokenValidator<>(
					new JwtClaimValidator<>(JwtClaimNames.ISS, clientId::equals),
					new JwtClaimValidator<>(JwtClaimNames.SUB, clientId::equals),
					new JwtClaimValidator<>(JwtClaimNames.AUD, containsProviderAudience()),
					new JwtClaimValidator<>(JwtClaimNames.EXP, Objects::nonNull),
					new JwtTimestampValidator()
			);
		}

		private Predicate<List<String>> containsProviderAudience() {
			return (audienceClaim) -> {
				if (CollectionUtils.isEmpty(audienceClaim)) {
					return false;
				}
				for (String audience : audienceClaim) {
					if (this.providerAudience.contains(audience)) {
						return true;
					}
				}
				return false;
			};
		}

		private static List<String> getProviderAudience(ProviderSettings providerSettings) {
			if (!StringUtils.hasText(providerSettings.getIssuer())) {
				return Collections.emptyList();
			}
			List<String> providerAudience = new ArrayList<>();
			providerAudience.add(providerSettings.getIssuer());
			providerAudience.add(asUrl(providerSettings.getIssuer(), providerSettings.getTokenEndpoint()));
			providerAudience.add(asUrl(providerSettings.getIssuer(), providerSettings.getTokenIntrospectionEndpoint()));
			providerAudience.add(asUrl(providerSettings.getIssuer(), providerSettings.getTokenRevocationEndpoint()));
			return providerAudience;
		}

		private static String asUrl(String issuer, String endpoint) {
			return UriComponentsBuilder.fromUriString(issuer).path(endpoint).build().toUriString();
		}

	}

}
