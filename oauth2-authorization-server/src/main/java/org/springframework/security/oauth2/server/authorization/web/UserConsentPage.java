package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * User Consent Page Interface
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

	default boolean isConsentApproved(HttpServletRequest request) {
		return CONSENT_ACTION_APPROVE.equalsIgnoreCase(request.getParameter(CONSENT_ACTION_PARAMETER_NAME));
	}

	default boolean isConsentCancelled(HttpServletRequest request) {
		return CONSENT_ACTION_CANCEL.equalsIgnoreCase(request.getParameter(CONSENT_ACTION_PARAMETER_NAME));
	}

	String generateConsentPage(HttpServletRequest request,
			RegisteredClient registeredClient, OAuth2Authorization authorization);

}
