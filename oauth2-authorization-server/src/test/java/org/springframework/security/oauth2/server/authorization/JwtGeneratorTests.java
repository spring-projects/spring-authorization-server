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
package org.springframework.security.oauth2.server.authorization;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link JwtGenerator}.
 *
 * @author Joe Grandja
 */
public class JwtGeneratorTests {
	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
	private JwtEncoder jwtEncoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;
	private JwtGenerator jwtGenerator;
	private ProviderContext providerContext;

	@Before
	public void setUp() {
		this.jwtEncoder = mock(JwtEncoder.class);
		this.jwtCustomizer = mock(OAuth2TokenCustomizer.class);
		this.jwtGenerator = new JwtGenerator(this.jwtEncoder);
		this.jwtGenerator.setJwtCustomizer(this.jwtCustomizer);
		ProviderSettings providerSettings = ProviderSettings.builder().issuer("https://provider.com").build();
		this.providerContext = new ProviderContext(providerSettings, null);
	}

	@Test
	public void constructorWhenJwtEncoderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwtGenerator(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtEncoder cannot be null");
	}

	@Test
	public void setJwtCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.jwtGenerator.setJwtCustomizer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtCustomizer cannot be null");
	}

	@Test
	public void generateWhenUnsupportedTokenTypeThenReturnNull() {
		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.tokenType(new OAuth2TokenType("unsupported_token_type"))
				.build();
		// @formatter:on

		assertThat(this.jwtGenerator.generate(tokenContext)).isNull();
	}

	@Test
	public void generateWhenAccessTokenTypeThenReturnJwt() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.providerContext(this.providerContext)
				.authorization(authorization)
				.authorizedScopes(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME))
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authentication)
				.build();
		// @formatter:on

		assertGeneratedTokenType(tokenContext);
	}

	@Test
	public void generateWhenIdTokenTypeThenReturnJwt() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		Map<String, Object> authenticationRequestAdditionalParameters = new HashMap<>();
		authenticationRequestAdditionalParameters.put(OidcParameterNames.NONCE, "nonce");
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(
				registeredClient, authenticationRequestAdditionalParameters).build();

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication =
				new OAuth2AuthorizationCodeAuthenticationToken("code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.providerContext(this.providerContext)
				.authorization(authorization)
				.authorizedScopes(authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME))
				.tokenType(ID_TOKEN_TOKEN_TYPE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authentication)
				.build();
		// @formatter:on

		assertGeneratedTokenType(tokenContext);
	}

	private void assertGeneratedTokenType(OAuth2TokenContext tokenContext) {
		this.jwtGenerator.generate(tokenContext);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer).customize(jwtEncodingContextCaptor.capture());

		JwtEncodingContext jwtEncodingContext = jwtEncodingContextCaptor.getValue();
		assertThat(jwtEncodingContext.getHeaders()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();
		assertThat(jwtEncodingContext.getRegisteredClient()).isEqualTo(tokenContext.getRegisteredClient());
		assertThat(jwtEncodingContext.<Authentication>getPrincipal()).isEqualTo(tokenContext.getPrincipal());
		assertThat(jwtEncodingContext.getAuthorization()).isEqualTo(tokenContext.getAuthorization());
		assertThat(jwtEncodingContext.getAuthorizedScopes()).isEqualTo(tokenContext.getAuthorizedScopes());
		assertThat(jwtEncodingContext.getTokenType()).isEqualTo(tokenContext.getTokenType());
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(tokenContext.getAuthorizationGrantType());
		assertThat(jwtEncodingContext.<Authentication>getAuthorizationGrant()).isEqualTo(tokenContext.getAuthorizationGrant());

		ArgumentCaptor<JoseHeader> joseHeaderCaptor = ArgumentCaptor.forClass(JoseHeader.class);
		ArgumentCaptor<JwtClaimsSet> jwtClaimsSetCaptor = ArgumentCaptor.forClass(JwtClaimsSet.class);
		verify(this.jwtEncoder).encode(joseHeaderCaptor.capture(), jwtClaimsSetCaptor.capture());

		JoseHeader joseHeader = joseHeaderCaptor.getValue();
		assertThat(joseHeader.<JwsAlgorithm>getAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);

		JwtClaimsSet jwtClaimsSet = jwtClaimsSetCaptor.getValue();
		assertThat(jwtClaimsSet.getIssuer().toExternalForm()).isEqualTo(tokenContext.getProviderContext().getIssuer());
		assertThat(jwtClaimsSet.getSubject()).isEqualTo(tokenContext.getAuthorization().getPrincipalName());
		assertThat(jwtClaimsSet.getAudience()).containsExactly(tokenContext.getRegisteredClient().getClientId());

		Instant issuedAt = Instant.now();
		Instant expiresAt;
		if (tokenContext.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
			expiresAt = issuedAt.plus(tokenContext.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
		} else {
			expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
		}
		assertThat(jwtClaimsSet.getIssuedAt()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));
		assertThat(jwtClaimsSet.getExpiresAt()).isBetween(expiresAt.minusSeconds(1), expiresAt.plusSeconds(1));

		if (tokenContext.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
			assertThat(jwtClaimsSet.getNotBefore()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));

			Set<String> scopes = jwtClaimsSet.getClaim(OAuth2ParameterNames.SCOPE);
			assertThat(scopes).isEqualTo(tokenContext.getAuthorizedScopes());
		} else {
			assertThat(jwtClaimsSet.<String>getClaim(IdTokenClaimNames.AZP)).isEqualTo(tokenContext.getRegisteredClient().getClientId());

			OAuth2AuthorizationRequest authorizationRequest = tokenContext.getAuthorization().getAttribute(
					OAuth2AuthorizationRequest.class.getName());
			String nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);
			assertThat(jwtClaimsSet.<String>getClaim(IdTokenClaimNames.NONCE)).isEqualTo(nonce);
		}
	}

}
