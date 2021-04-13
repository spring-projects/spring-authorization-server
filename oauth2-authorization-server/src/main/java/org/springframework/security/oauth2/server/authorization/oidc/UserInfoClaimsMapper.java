package org.springframework.security.oauth2.server.authorization.oidc;

import java.util.Map;

public interface UserInfoClaimsMapper {

	Map<String, Object> map(Object principal);

}
