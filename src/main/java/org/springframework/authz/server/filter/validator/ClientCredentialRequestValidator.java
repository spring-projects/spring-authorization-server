package org.springframework.authz.server.filter.validator;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.util.Strings;
import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;

public class ClientCredentialRequestValidator implements RequestValidator{
	
	private static final ValidationException AUTH_HEADER_ABSENT_EXP = new ValidationException("Authorization Header is absent from the request. Client Credential check cannot be performed");
	private static final ValidationException AUTH_HEADER_INVALID_TYPE_EXP = new ValidationException("Authorization Header authorization type should be Basic for Client Credentials check.");
	
	private static final String AUTHORIZATION_TYPE = "Basic";

	@Override
	public boolean isValidRequest(HttpServletRequest request) throws ValidationException {
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if(StringUtils.isEmpty(authorizationHeader)) 
			throw AUTH_HEADER_ABSENT_EXP;
		
		if (!StringUtils.startsWithIgnoreCase(authorizationHeader, AUTHORIZATION_TYPE)) 
			throw AUTH_HEADER_INVALID_TYPE_EXP;
		
		return true;
	}

}
