package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * User Consent Page
 *
 * @author shanhy
 * @date 2021/3/30 15:42
 */
public interface UserConsentPage {

	String CONSENT_ACTION_PARAMETER_NAME = "consent_action";
	String CONSENT_ACTION_APPROVE = "approve";
	String CONSENT_ACTION_CANCEL = "cancel";

	void displayConsent(HttpServletRequest request, HttpServletResponse response,
			RegisteredClient registeredClient, OAuth2Authorization authorization) throws IOException;

	boolean isConsentApproved(HttpServletRequest request);

	boolean isConsentCancelled(HttpServletRequest request);

	String generateConsentPage(HttpServletRequest request,
			RegisteredClient registeredClient, OAuth2Authorization authorization);

}
