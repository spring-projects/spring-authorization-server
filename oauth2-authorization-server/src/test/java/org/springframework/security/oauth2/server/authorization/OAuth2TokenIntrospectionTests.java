package org.springframework.security.oauth2.server.authorization;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class OAuth2TokenIntrospectionTests {

	@Test
	void buildWhenIssuerIsNonUriStringThenDoesNotThrow() {
		String issuer = "client-id-123"; // plain string, not a URI

		assertThatCode(() -> {
			OAuth2TokenIntrospection token =
					OAuth2TokenIntrospection.builder(true)
							.issuer(issuer)
							.subject("user-123")
							.build();

			Object issClaim = token.getClaim(OAuth2TokenIntrospectionClaimNames.ISS);
			assertThat(issClaim).isEqualTo(issuer);

			Object activeClaim = token.getClaim(OAuth2TokenIntrospectionClaimNames.ACTIVE);
			assertThat(activeClaim).isEqualTo(true);
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
		assertThat(issClaim).isEqualTo(issuer);

		Object activeClaim = token.getClaim(OAuth2TokenIntrospectionClaimNames.ACTIVE);
		assertThat(activeClaim).isEqualTo(true);
	}

	@Test
	void buildWithMultipleScopes() {
		OAuth2TokenIntrospection token =
				OAuth2TokenIntrospection.builder(true)
						.scope("read")
						.scope("write")
						.build();

		List<String> scopes = (List<String>) token.getClaim(OAuth2TokenIntrospectionClaimNames.SCOPE);
		assertThat(scopes).containsExactly("read", "write");
	}

	@Test
	void buildWhenIssuerIsBlankThenThrowsException() {
		String issuer = "   "; // blank string

		assertThatThrownBy(() ->
				OAuth2TokenIntrospection.builder(true)
						.issuer(issuer)
						.subject("user-123")
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}
}
