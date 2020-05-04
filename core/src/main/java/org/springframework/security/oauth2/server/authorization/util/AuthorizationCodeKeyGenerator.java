package org.springframework.security.oauth2.server.authorization.util;

import java.util.UUID;

import org.springframework.security.crypto.keygen.StringKeyGenerator;

/**
 * @author Paurav Munshi
 * @since 0.0.1
 */
public class AuthorizationCodeKeyGenerator implements StringKeyGenerator {

	@Override
	public String generateKey() {
		// TODO Auto-generated method stub
		return UUID.randomUUID().toString();
	}

}
