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

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/**
 * Default implementation for the {@link RedirectValidator}.
 *
 * @author Anoop Garlapati
 * @since 0.1.1
 */
public class DefaultRedirectValidator implements RedirectValidator {

	private static final Pattern LOOPBACK_ADDRESS_PATTERN =
			Pattern.compile("^localhost$|^127(?:\\.[0-9]+){0,2}\\.[0-9]+$|^(?:0*:)*?:?0*1$");

	public boolean validate(String requestedRedirectUri, RegisteredClient registeredClient) {
		try {
			URI requestedRedirectURI = new URI(requestedRedirectUri);
			if (requestedRedirectURI.getFragment() != null) {
				return false;
			}
		} catch (URISyntaxException ex) {
			return false;
		}

		UriComponents requestedRedirect = UriComponentsBuilder.fromUriString(requestedRedirectUri).build();

		if (!isLoopbackAddress(requestedRedirect)) {
			// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-9.7
			// When comparing client redirect URIs against pre-registered URIs,
			// authorization servers MUST utilize exact string matching.
			return registeredClient.getRedirectUris().contains(requestedRedirectUri);
		}

		// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-10.3.3
		// The authorization server MUST allow any port to be specified at the
		// time of the request for loopback IP redirect URIs, to accommodate
		// clients that obtain an available ephemeral port from the operating
		// system at the time of the request.
		for (String registeredRedirect : registeredClient.getRedirectUris()) {
			UriComponentsBuilder redirectUriToMatch = UriComponentsBuilder.fromUriString(registeredRedirect);
			redirectUriToMatch.port(requestedRedirect.getPort());
			if (redirectUriToMatch.build().toString().equals(requestedRedirect.toString())) {
				return true;
			}
		}
		return false;
	}

	private boolean isLoopbackAddress(UriComponents requestedRedirect) {
		String host = requestedRedirect.getHost();
		if (host == null) {
			return false;
		}
		return LOOPBACK_ADDRESS_PATTERN.matcher(host).matches();
	}
}
