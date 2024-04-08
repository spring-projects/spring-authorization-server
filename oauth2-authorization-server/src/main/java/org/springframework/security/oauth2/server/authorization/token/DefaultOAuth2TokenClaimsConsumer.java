/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.token;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

/**
 * @author Joe Grandja
 * @since 1.3
 */
final class DefaultOAuth2TokenClaimsConsumer implements Consumer<Map<String, Object>> {
	private static final ClientAuthenticationMethod TLS_CLIENT_AUTH_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("tls_client_auth");
	private static final ClientAuthenticationMethod SELF_SIGNED_TLS_CLIENT_AUTH_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("self_signed_tls_client_auth");
	private final OAuth2TokenContext context;

	DefaultOAuth2TokenClaimsConsumer(OAuth2TokenContext context) {
		this.context = context;
	}

	@Override
	public void accept(Map<String, Object> claims) {
		// Add 'cnf' claim for Mutual-TLS Client Certificate-Bound Access Tokens
		if (OAuth2TokenType.ACCESS_TOKEN.equals(this.context.getTokenType()) &&
				this.context.getAuthorizationGrant() != null &&
				this.context.getAuthorizationGrant().getPrincipal() instanceof OAuth2ClientAuthenticationToken clientAuthentication) {

			if ((TLS_CLIENT_AUTH_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod()) ||
					SELF_SIGNED_TLS_CLIENT_AUTH_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) &&
					this.context.getRegisteredClient().getTokenSettings().isX509CertificateBoundAccessTokens()) {

				X509Certificate[] clientCertificateChain = (X509Certificate[]) clientAuthentication.getCredentials();
				try {
					String sha256Thumbprint = computeSHA256Thumbprint(clientCertificateChain[0]);
					Map<String, Object> x5tClaim = new HashMap<>();
					x5tClaim.put("x5t#S256", sha256Thumbprint);
					claims.put("cnf", x5tClaim);
				} catch (Exception ex) {
					OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
							"Failed to compute SHA-256 Thumbprint for client X509Certificate.", null);
					throw new OAuth2AuthenticationException(error, ex);
				}
			}
		}
	}

	private static String computeSHA256Thumbprint(X509Certificate x509Certificate) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(x509Certificate.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
