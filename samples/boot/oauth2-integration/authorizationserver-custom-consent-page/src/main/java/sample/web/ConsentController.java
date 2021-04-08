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
package sample.web;

import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Daniel Garnier-Moiroux
 * @since 0.1.2
 */
@Controller
public class ConsentController {

	private final OAuth2AuthorizationConsentService authorizationConsentService;

	public ConsentController(OAuth2AuthorizationConsentService authorizationConsentService) {
		this.authorizationConsentService = authorizationConsentService;
	}

	@GetMapping(value = "/consent")
	public String consent(
			Principal principal,
			Model model,
			@RequestParam(OAuth2ParameterNames.SCOPE) String scope,
			@RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
			@RequestParam(OAuth2ParameterNames.STATE) String state
	) {
		// Remove scopes that were already approved
		Set<String> scopesToApprove = new HashSet<>();
		Set<String> previouslyApprovedScopes = new HashSet<>();
		OAuth2AuthorizationConsent previousConsent = this.authorizationConsentService.findById(clientId, principal.getName());
		for (String scopeFromRequest : StringUtils.delimitedListToStringArray(scope, " ")) {
			if (previousConsent != null && previousConsent.getScopes().contains(scopeFromRequest)) {
				previouslyApprovedScopes.add(scopeFromRequest);
			} else {
				scopesToApprove.add(scopeFromRequest);
			}
		}

		model.addAttribute("state", state);
		model.addAttribute("clientId", clientId);
		model.addAttribute("scopes", withDescription(scopesToApprove));
		model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
		model.addAttribute("principalName", principal.getName());

		return "consent";
	}

	private Set<ScopeWithDescription> withDescription(Set<String> scopes) {
		return scopes
				.stream()
				.map(ScopeWithDescription::new)
				.collect(Collectors.toSet());
	}

	private static class ScopeWithDescription {
		public final String scope;
		public final String description;

		private final static String DEFAULT_DESCRIPTION = "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this.";
		private static final Map<String, String> scopeDescriptions = new HashMap<>();
		static {
			scopeDescriptions.put(
					"message.read",
					"This application will be able to read your message."
			);
			scopeDescriptions.put(
					"message.write",
					"This application will be able to add new messages. It will also be able to edit and delete existing messages."
			);
			scopeDescriptions.put(
					"other.scope",
					"This is another scope example of a scope description."
			);
		}

		ScopeWithDescription(String scope) {
			this.scope = scope;
			this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
		}
	}
}
