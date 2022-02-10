package com.accesso.security.oauth2.server.authorization.authentication;

import com.accesso.security.oauth2.server.authorization.config.ClientExternalAuthenticationConfig;
import com.accesso.security.oauth2.server.authorization.config.ClientExternalAuthenticationConfig.ClientExternalAuthConfig;
import jdk.nashorn.internal.runtime.Scope;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This class extends the basic functionality of the LoginUrlAuthenticationEntryPoint class
 * that is used to redirect users to a login form when a username/password must be acquired.
 * Its purpose it to make it possible, via additional configuration to redirect users to an
 * external OAuth2 authentication URL (i.e. for federated identity) based on the data avaialble
 * for the HttpRequest (e.g. such as the hostname or a 'tenant' http header.)
 */
public class AccessoLoginUrlAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	private Map<String,ClientExternalAuthConfig> config;
	private ScopeMapper mapper = new ScopeMapper();

	/**
	 * @param loginFormUrl URL where the login page can be found. Should either be
	 *                     relative to the web-app context path (include a leading {@code /}) or an absolute
	 *                     URL.
	 */
	public AccessoLoginUrlAuthenticationEntryPoint(String ourLoginFormUrl, ClientExternalAuthenticationConfig authConfig) {
		super(ourLoginFormUrl);
		this.config = authConfig.getConfig();
	}

	/**
	 * Returns the URL to redirect the browser to, for a given HttpServletRequest
	 * @param request
	 * @param response
	 * @param exception
	 * @return
	 */
	@Override
	protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) {
		// Because this login URL class is only called by the Spring Security exception handler in response to an
		// unauthenticated end user, it always knows the client (and has authenticated the client) by the time
		// we get here, so this will be available:
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
		ClientExternalAuthenticationConfig.ClientExternalAuthConfig clientExternalConfig = this.config.get(clientId);
		if (clientExternalConfig == null) {
			// We serve the login page.
			return super.determineUrlToUseForThisRequest(request, response, exception);
		}

		// TODO - in a full implementation of this "issuerUrl" would be used to pull the openid-configuration
		// data in full, so we would have all the endpoints and that way we just need to have that correct.
		final String authorizationRequestUri = UriComponentsBuilder
				.fromUriString( clientExternalConfig.getIssuerUri() )
				.queryParam(OAuth2ParameterNames.RESPONSE_TYPE, request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
				.queryParam(OAuth2ParameterNames.CLIENT_ID, clientExternalConfig.getExtClientId())
				.queryParam(OAuth2ParameterNames.SCOPE,
						String.join(" ", mapper.mapScopes(clientExternalConfig, request.getParameterValues(OAuth2ParameterNames.SCOPE))))
				.queryParam(OAuth2ParameterNames.STATE, request.getParameter(OAuth2ParameterNames.STATE))
				.queryParam(OAuth2ParameterNames.REDIRECT_URI, request.getParameter(OAuth2ParameterNames.REDIRECT_URI))
				.toUriString();
		return authorizationRequestUri;
	}

}
