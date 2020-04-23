package org.springframework.authz.server.filter.matcher;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.authz.server.config.OAuthConstants;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class GrantTypeReqMatcher implements RequestMatcher{
	
	private Set<String> grantsAllowed = new HashSet<String>();
	public GrantTypeReqMatcher(String[] allowedGrants) {
		if(allowedGrants.length > 0) 
			Stream.of(allowedGrants).forEach(grant -> grantsAllowed.add(grant));
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		String grantType = request.getParameter(OAuthConstants.GARNT_TYPE_PARAM);
		return grantsAllowed.contains(grantType);
	}

}
