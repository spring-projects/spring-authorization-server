package org.springframework.authz.server.filter.validator;

public class ValidationException extends Exception {
	public ValidationException(String message) {
		super(message);
	}
}
