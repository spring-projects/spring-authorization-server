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
package org.springframework.security.oauth2.server.authorization.authentication;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2ClientAuthenticationProvider.RegisteredClientJwtAssertionDecoderFactory}
 *
 * @author Rafal Lewczuk
 */
public class RegisteredClientJwtAssertionDecoderFactoryTests {

	private JwtDecoderFactory<RegisteredClient> registeredClientDecoderFactory;

	@Before
	public void setUp() {
		OAuth2ClientAuthenticationProvider authenticationProvider = new OAuth2ClientAuthenticationProvider(
				mock(RegisteredClientRepository.class), mock(OAuth2AuthorizationService.class));
		this.registeredClientDecoderFactory = (JwtDecoderFactory<RegisteredClient>)
				ReflectionTestUtils.getField(authenticationProvider, "jwtDecoderFactory");
	}

	@Test
	public void createDecoderWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> registeredClientDecoderFactory.createDecoder(null))
				.withMessage("registeredClient cannot be null");
	}

	@Test
	public void createDecoderWhenClientAuthenticationMethodNotSupportedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		assertThatThrownBy(() -> this.registeredClientDecoderFactory.createDecoder(registeredClient))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void createDecoderWithClientSecretJwtWhenClientSecretNullThenThrowOAuth2Exception() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build())
				.build();

		assertThatThrownBy(() -> this.registeredClientDecoderFactory.createDecoder(registeredClient))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void createDecoderWithClientSecretJwtClientThenReturnDecoder() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret("0123456789abcdef0123456789ABCDEF")
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build())
				.build();

		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);

		assertThat(jwtDecoder).isNotNull();
	}

	@Test
	public void createDecoderWithClientSecretJwtTwiceThenReturnCachedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret("0123456789abcdef0123456789ABCDEF")
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build());

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(registeredClientBuilder.build());
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(registeredClientBuilder.build());

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isSameAs(decoder1);
	}

	@Test
	public void createDecoderWithClientSecretJwtAndSecondWithChangedAlgorithmThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret("0123456789abcdef0123456789ABCDEF");
		RegisteredClient registeredClient1 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build()).build();
		RegisteredClient registeredClient = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS512).build()).build();

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(registeredClient1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(registeredClient);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithClientSecretJwtAndSecondWithChangedSecretThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build());
		RegisteredClient registeredClient1 = registeredClientBuilder.clientSecret("0123456789abcdef0123456789ABCDEF").build();
		RegisteredClient registeredClient2 = registeredClientBuilder.clientSecret("0123456789ABCDEF0123456789abcdef").build();

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(registeredClient1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(registeredClient2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtMissingJwksUrlThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientSettings(ClientSettings.builder()
						.tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256).build())
				.build();

		assertThatThrownBy(() -> this.registeredClientDecoderFactory.createDecoder(registeredClient))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtThenReturnDecoder() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientSettings(ClientSettings.builder()
						.tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256).jwkSetUrl("https://client.example.com/jwks").build())
				.build();

		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);

		assertThat(jwtDecoder).isNotNull();
	}

	@Test
	public void createDecoderWithPrivateKeyJwtAndSecondWithChangedAlgorithmThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);

		RegisteredClient registeredClient1 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256)
						.jwkSetUrl("https://keysite.com/jwks").build()).build();
		RegisteredClient registeredClient2 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS512)
						.jwkSetUrl("https://keysite.com/jwks").build()).build();

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(registeredClient1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(registeredClient2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtAndSecondWithChangedJwksUrlThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);

		RegisteredClient client1 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256)
						.jwkSetUrl("https://keysite1.com/jwks").build()).build();
		RegisteredClient client2 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256)
						.jwkSetUrl("https://keysite2.com/jwks").build()).build();

		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(client1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(client2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtNullAlgorithmThenReturnDefaultRS256Decoder() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl("https://keysite1.com/jwks")
								.build())
				.build();

		JwtDecoder decoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		assertThat(decoder).isNotNull();
	}

	@Test
	public void validateClientSecretJwtTokenWhenValidThenReturnJwtObject() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.issuer(registeredClient.getClientId())
						.subject(registeredClient.getClientId())
						.expirationTime(Date.from(Instant.now()))
						.build());

		assertThat(jwtDecoder.decode(clientJwtAssertion)).isNotNull();
	}

	@Test
	public void validateClientSecretJwtTokenWhenBadIssuerThenThrowJwtException() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.issuer("bad-issuer")
						.subject(registeredClient.getClientId())
						.expirationTime(Date.from(Instant.now()))
						.build());

		assertThatThrownBy(() -> jwtDecoder.decode(clientJwtAssertion))
				.isInstanceOf(JwtException.class)
				.extracting("message")
				.matches(s -> s.toString().contains("The iss claim is not valid"));
	}

	@Test
	public void validateClientSecretJwtTokenWhenBadSubjectThenThrowJwtException() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.issuer(registeredClient.getClientId())
						.subject("bad-client")
						.expirationTime(Date.from(Instant.now()))
						.build());

		assertThatThrownBy(() -> jwtDecoder.decode(clientJwtAssertion))
				.isInstanceOf(JwtException.class)
				.extracting("message")
				.matches(s -> s.toString().contains("The sub claim is not valid"));
	}

	@Test
	public void validateClientSecretJwtTokenWhenNoExpClaimThenThrowJwtException() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.subject(registeredClient.getClientId())
						.issuer(registeredClient.getClientId())
						.build());

		assertThatThrownBy(() -> jwtDecoder.decode(clientJwtAssertion))
				.isInstanceOf(JwtException.class)
				.extracting("message")
				.matches(s -> s.toString().contains("The exp claim is not valid"));
	}

	@Test
	public void validateClientSecretJwtTokenWhenExpiredThenThrowJwtException() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.subject(registeredClient.getClientId())
						.issuer(registeredClient.getClientId())
						.expirationTime(Date.from(Instant.now().minusSeconds(240)))
						.build());

		assertThatThrownBy(() -> jwtDecoder.decode(clientJwtAssertion))
				.isInstanceOf(JwtException.class)
				.extracting("message")
				.matches(s -> s.toString().contains("Jwt expired at"));
	}

	@Test
	public void validateClientSecretJwtTokenWhenExpiredWithinSkewThenReturnJwtObject() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.subject(registeredClient.getClientId())
						.issuer(registeredClient.getClientId())
						.expirationTime(Date.from(Instant.now().minusSeconds(30)))
						.build());

		assertThat(jwtDecoder.decode(clientJwtAssertion)).isNotNull();
	}

	@Test
	public void validateClientSecretJwtTokenWhenInvalidNbfThenThrowJwtException() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.subject(registeredClient.getClientId())
						.issuer(registeredClient.getClientId())
						.expirationTime(Date.from(Instant.now()))
						.notBeforeTime(Date.from(Instant.now().plusSeconds(90)))
						.build());

		assertThatThrownBy(() -> jwtDecoder.decode(clientJwtAssertion))
				.isInstanceOf(JwtException.class)
				.extracting("message")
				.matches(s -> s.toString().contains("Jwt used before"));
	}

	@Test
	public void validateClientSecretJwtTokenWhenInvalidIatThenThrowJwtException() throws Exception {
		RegisteredClient registeredClient = defaultRegisteredClient();
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);
		String clientJwtAssertion = clientSecretJwtAssertion(registeredClient,
				new JWTClaimsSet.Builder()
						.subject(registeredClient.getClientId())
						.issuer(registeredClient.getClientId())
						.expirationTime(Date.from(Instant.now()))
						.issueTime(Date.from(Instant.now().plusSeconds(90)))
						.build());

		assertThatThrownBy(() -> jwtDecoder.decode(clientJwtAssertion))
				.isInstanceOf(JwtException.class)
				.extracting("message")
				.matches(s -> s.toString().contains("expiresAt must be after issuedAt"));
	}

	@Test
	public void validatePrivateKeyJwtTokenWhenValidThenReturnJwtObject() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keyPair = gen.generateKeyPair();

		JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.keyUse(KeyUse.SIGNATURE)
				.keyID(UUID.randomUUID().toString())
				.build();

		String jwks = "{\"keys\":[" + jwk.toJSONString() + "]}";

		try (MockWebServer server = new MockWebServer()) {
			String jwkSetUrl = server.url("/.well-known/jwks.json").toString();
			server.enqueue(new MockResponse().setBody(jwks));

			RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
					.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
					.clientSettings(ClientSettings.builder()
							.tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256)
							.jwkSetUrl(jwkSetUrl).build())
					.build();

			JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(registeredClient);

			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.issuer(registeredClient.getClientId())
					.subject(registeredClient.getClientId())
					.expirationTime(Date.from(Instant.now()))
					.build();
			SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
			JWSSigner signer = new RSASSASigner(keyPair.getPrivate());
			signedJWT.sign(signer);
			String clientJwtAssertion = signedJWT.serialize();

			assertThat(jwtDecoder.decode(clientJwtAssertion)).isNotNull();

			server.shutdown();
		}

	}

	private RegisteredClient defaultRegisteredClient() {
		return TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret("0123456789abcdef0123456789ABCDEF")
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build())
				.build();
	}

	private String clientSecretJwtAssertion(RegisteredClient registeredClient, JWTClaimsSet claimsSet) throws JOSEException {
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		JWSSigner signer = new MACSigner(registeredClient.getClientSecret().getBytes(StandardCharsets.UTF_8));
		signedJWT.sign(signer);
		String clientJwtAssertion = signedJWT.serialize();
		return clientJwtAssertion;
	}
}
