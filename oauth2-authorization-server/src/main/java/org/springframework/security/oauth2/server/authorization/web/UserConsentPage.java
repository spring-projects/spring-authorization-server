/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

	/**
	 * Output and display consent
	 *
	 * @param request
	 * @param response
	 * @param registeredClient
	 * @param authorization
	 *
	 * @throws IOException
	 */
	void displayConsent(HttpServletRequest request, HttpServletResponse response,
			RegisteredClient registeredClient, OAuth2Authorization authorization) throws IOException;

	/**
	 * Is Consent Approved
	 *
	 * @param request
	 * @return
	 */
	default boolean isConsentApproved(HttpServletRequest request) {
		return CONSENT_ACTION_APPROVE.equalsIgnoreCase(request.getParameter(CONSENT_ACTION_PARAMETER_NAME));
	}

	/**
	 * Is Consent Cancelled
	 *
	 * @param request
	 * @return
	 */
	default boolean isConsentCancelled(HttpServletRequest request) {
		return CONSENT_ACTION_CANCEL.equalsIgnoreCase(request.getParameter(CONSENT_ACTION_PARAMETER_NAME));
	}

	/**
	 * Generate Consent Page HTML Code
	 *
	 * @param request
	 * @param registeredClient
	 * @param authorization
	 * @return HTML Code
	 */
	String generateConsentPage(HttpServletRequest request,
			RegisteredClient registeredClient, OAuth2Authorization authorization);

}
