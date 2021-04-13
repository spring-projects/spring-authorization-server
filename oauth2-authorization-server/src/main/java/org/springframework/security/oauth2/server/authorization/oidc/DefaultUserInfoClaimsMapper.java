package org.springframework.security.oauth2.server.authorization.oidc;

import java.util.Collections;
import java.util.Map;

public class DefaultUserInfoClaimsMapper implements UserInfoClaimsMapper {

	public Map<String, Object> map(Object principal) {
		return Collections.emptyMap(); // TODO
	}

}
