package com.accesso.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Sample token customizer.  The type of the authentication token that has been generated (e.g. by different
 * APIs) can be seen and this bean can in turn use any resources required e.g. UserDetails in order to have the
 * details that would normally be needed.
 */
public class AccessoAccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	static final List<Map<String, String>> anonymous_amr = Collections.singletonList(Collections.singletonMap("authority", "anonymous"));
	static final List<Map<String, String>> credentials_amr = Collections.singletonList(Collections.singletonMap("authority", "credentials"));

	@Override
	public void customize(JwtEncodingContext context) {
		Authentication token = context.getPrincipal();
		JwtClaimsSet.Builder claims = context.getClaims();
		additionalAttributes(token).forEach(claims::claim);
	}

	Map<String, Object> additionalAttributes(Authentication authentication) {
		HashMap<String, Object> props = new HashMap<>();
		if (authentication instanceof AnonymousAuthenticationToken) {
			customizeAnonymousToken((AnonymousAuthenticationToken) authentication, props);
		} else if (authentication instanceof OAuth2ClientAuthenticationToken) {
			customizeClientToken((OAuth2ClientAuthenticationToken) authentication, props);
		}
		return props;
	}

	private void customizeAnonymousToken(AnonymousAuthenticationToken anonymousToken,
			Map<String, Object> additionalProps) {
		additionalProps.put("amr", anonymous_amr);
		additionalProps.put("uuid", anonymousToken.getPrincipal());
		additionalProps.put("user_type", "Guests");
	}

	private void customizeClientToken(OAuth2ClientAuthenticationToken clientToken,
			Map<String, Object> additionalProps) {
		additionalProps.put("amr", credentials_amr);
		additionalProps.put("user_type", "Service");
	}
}
