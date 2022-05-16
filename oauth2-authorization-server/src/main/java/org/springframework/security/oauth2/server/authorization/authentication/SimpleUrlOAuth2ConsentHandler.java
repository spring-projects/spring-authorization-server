/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.io.IOException;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class SimpleUrlOAuth2ConsentHandler implements
		OAuth2ConsentHandler {

	private String consentPage;
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public SimpleUrlOAuth2ConsentHandler() {
	}

	public SimpleUrlOAuth2ConsentHandler(String consentPage) {
		this.consentPage = consentPage;
	}


	@Override
	public void handleConsent(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult)
			throws IOException {
		String clientId = authorizationCodeRequestAuthenticationResult.getClientId();
		Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
		String state = authorizationCodeRequestAuthenticationResult.getState();
		String redirectUri = UriComponentsBuilder.fromUriString(resolveConsentUri(request))
				.queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", requestedScopes))
				.queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
				.queryParam(OAuth2ParameterNames.STATE, state)
				.toUriString();
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

	private String resolveConsentUri(HttpServletRequest request) {
		if (UrlUtils.isAbsoluteUrl(this.consentPage)) {
			return this.consentPage;
		}
		RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
		urlBuilder.setScheme(request.getScheme());
		urlBuilder.setServerName(request.getServerName());
		urlBuilder.setPort(request.getServerPort());
		urlBuilder.setContextPath(request.getContextPath());
		urlBuilder.setPathInfo(this.consentPage);
		return urlBuilder.getUrl();
	}

	public void setConsentPage(String consentPage) {
		this.consentPage = consentPage;
	}

	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}
}
