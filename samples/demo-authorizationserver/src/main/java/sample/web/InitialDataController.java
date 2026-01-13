package sample.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import sample.service.JdbcUserService;

import java.util.UUID;

@Controller
public class InitialDataController {

	@PostMapping("/initial-data")
	public ResponseEntity<Void> initialData(
			JdbcRegisteredClientRepository registeredClientRepository,
			JdbcUserService jdbcUserService
			)
	{
		RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://localhost:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://localhost:8080/authorized")
				.postLogoutRedirectUri("http://localhost:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.scope("user.read")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();

		// Save registered client's in db
		registeredClientRepository.save(messagingClient);

		if (!jdbcUserService.userExists("user1")) {
			UserDetails user = User.withDefaultPasswordEncoder()
					.username("user1")
					.password("password")
					.roles("USER")
					.build();
			jdbcUserService.createUser(user);
		}

		return ResponseEntity.status(HttpStatus.OK).build();
	}

}
