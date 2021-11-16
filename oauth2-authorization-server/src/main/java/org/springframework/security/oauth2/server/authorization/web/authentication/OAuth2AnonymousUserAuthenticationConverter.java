package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AnonymousUserGrantAuthenticationToken;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * OAuth2 extension, grant_type=urn:accesso:oauth2:grant-type:anonymous, which returns a token and
 * identity (profile) for an as of yet unknown / unauthenticated end user on some personal device.
 * Attempts to extract an Anonymous Token Request from {@link HttpServletRequest}
 * and then converts it to an {@link OAuth2AnonymousUserGrantAuthenticationToken} used for authenticating the authorization grant.
 *
 * @author Bob Walters
 * @since 0.1.2
 * @see AuthenticationConverter
 * @see OAuth2AnonymousUserGrantAuthenticationToken
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2AnonymousUserAuthenticationConverter implements AuthenticationConverter {

	public static final AuthorizationGrantType ANONYMOUS_GRANT = new AuthorizationGrantType("urn:accesso:oauth2:grant-type:anonymous");

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		// grant_type (REQUIRED)
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!ANONYMOUS_GRANT.getValue().equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// scope (OPTIONAL)
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope) &&
				parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			OAuth2EndpointUtils.throwError(
					OAuth2ErrorCodes.INVALID_REQUEST,
					OAuth2ParameterNames.SCOPE,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}
		Set<String> requestedScopes = null;
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(
					Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		// additional parameters (OPTIONAL)
		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
					!key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		return new OAuth2AnonymousUserGrantAuthenticationToken(clientPrincipal, requestedScopes, additionalParameters);
	}

}
