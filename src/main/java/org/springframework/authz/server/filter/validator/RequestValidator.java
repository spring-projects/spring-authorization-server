package org.springframework.authz.server.filter.validator;

import javax.servlet.http.HttpServletRequest;

public interface RequestValidator {
	
	public boolean isValidRequest(HttpServletRequest request) throws ValidationException;

}