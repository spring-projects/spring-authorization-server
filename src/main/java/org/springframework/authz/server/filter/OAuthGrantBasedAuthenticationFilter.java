package org.springframework.authz.server.filter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.authz.server.filter.validator.RequestValidator;
import org.springframework.authz.server.filter.validator.ValidationException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

public class OAuthGrantBasedAuthenticationFilter extends AbstractAuthenticationProcessingFilter implements InitializingBean {
	
	private static final String DEFAULT_TOKEN_ENDPOINT = "/token";
	
	private static final RequestValidator SILENT_VALIDATOR = new SilentRequestValidator();
	
	private AuthenticationConverter reqConverter;
	private RequestMatcher reqGrantMatcher;
	private RequestValidator reqValidator = SILENT_VALIDATOR;

	public RequestValidator getReqValidator() {
		return reqValidator;
	}

	public void setReqValidator(RequestValidator reqValidator) {
		this.reqValidator = reqValidator;
	}

	public AuthenticationConverter getReqConverter() {
		return reqConverter;
	}

	public void setReqConverter(AuthenticationConverter reqConverter) {
		this.reqConverter = reqConverter;
	}

	public RequestMatcher getReqGrantMatcher() {
		return reqGrantMatcher;
	}

	public void setReqGrantMatcher(RequestMatcher reqGrantMatcher) {
		this.reqGrantMatcher = reqGrantMatcher;
	}

	

	public OAuthGrantBasedAuthenticationFilter() {
		super(DEFAULT_TOKEN_ENDPOINT);
		
	}
	
	public OAuthGrantBasedAuthenticationFilter(String endpoint) {
		super(endpoint);
		
	}
	
	public void afterPropertiesSet() {
		Assert.notNull(reqConverter, "RequestConverter cannot be null");
		Assert.notNull(reqGrantMatcher, "Request grant matcher cannot be null");
		Assert.notNull(reqValidator, "Request Validator cannot be null");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {		
		
		validateRequest(request);
		Authentication authenticationReq = reqConverter.convert(request);
		
		return Optional.ofNullable(authenticationReq)
			.map(auth -> this.getAuthenticationManager().authenticate(auth))
			.orElseThrow(() -> new AuthenticationServiceException("Error Authenticating OAuth request"));
	}
	
	private boolean validateRequest(HttpServletRequest request) throws AuthenticationException {
		boolean isValid = false;
		try {
			isValid = reqValidator.isValidRequest(request);
		}catch(ValidationException vexp) {
			throw new AuthenticationServiceException(vexp.getMessage());
		}
		
		return isValid;
		
	}

	protected boolean requiresAuthentication(HttpServletRequest request,
			HttpServletResponse response) {
		boolean isRequired = super.requiresAuthentication(request, response);
		if(isRequired) isRequired = reqGrantMatcher.matches(request);
		return isRequired;
	}
	
	static class SilentRequestValidator implements RequestValidator {

		@Override
		public boolean isValidRequest(HttpServletRequest request) throws ValidationException {
			// TODO Auto-generated method stub
			return true;
		}
		
	}
	
	

}