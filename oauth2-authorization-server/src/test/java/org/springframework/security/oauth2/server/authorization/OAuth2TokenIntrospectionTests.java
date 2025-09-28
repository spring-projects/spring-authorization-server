package org.springframework.security.oauth2.server.authorization;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;

import java.util.List;

public class OAuth2TokenIntrospectionTests {

	@Test
	void buildWhenIssuerIsNonUriStringThenDoesNotThrow() {
		String issuer = "client-id-123"; // plain string, not a URI

		org.assertj.core.api.Assertions.assertThatCode(() -> {
			OAuth2TokenIntrospection token =
					OAuth2TokenIntrospection.builder(true)
							.issuer(issuer)
							.subject("user-123")
							.build();

			Object issClaim = token.getClaim(OAuth2TokenIntrospectionClaimNames.ISS);
			org.assertj.core.api.Assertions.assertThat(issClaim).isEqualTo(issuer);

			Object activeClaim = token.getClaim(OAuth2TokenIntrospectionClaimNames.ACTIVE);
			org.assertj.core.api.Assertions.assertThat(activeClaim).isEqualTo(true);
		}).doesNotThrowAnyException();
	}

	@Test
	void buildWhenIssuerIsValidUriThenAcceptsIssuer() {
		String issuer = "https://issuer.example.com";

		OAuth2TokenIntrospection token =
				OAuth2TokenIntrospection.builder(true)
						.issuer(issuer)
						.subject("user-123")
						.build();

		Object issClaim = token.getClaim(OAuth2TokenIntrospectionClaimNames.ISS);
		org.assertj.core.api.Assertions.assertThat(issClaim).isEqualTo(issuer);

		Object activeClaim = token.getClaim(OAuth2TokenIntrospectionClaimNames.ACTIVE);
		org.assertj.core.api.Assertions.assertThat(activeClaim).isEqualTo(true);
	}

	@Test
	void buildWithMultipleScopes() {
		OAuth2TokenIntrospection token =
				OAuth2TokenIntrospection.builder(true)
						.scope("read")
						.scope("write")
						.build();

		List<String> scopes = (List<String>) token.getClaim(OAuth2TokenIntrospectionClaimNames.SCOPE);
		org.assertj.core.api.Assertions.assertThat(scopes).containsExactly("read", "write");
	}
}
