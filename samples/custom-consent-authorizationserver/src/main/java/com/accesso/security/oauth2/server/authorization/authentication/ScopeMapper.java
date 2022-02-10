package com.accesso.security.oauth2.server.authorization.authentication;

import com.accesso.security.oauth2.server.authorization.config.ClientExternalAuthenticationConfig;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class ScopeMapper {

	public Set<String> mapScopes(ClientExternalAuthenticationConfig.ClientExternalAuthConfig clientConfig,
			Iterable<String> parameterValues) {
		Set<String> scopesRequested = new HashSet<>();
		for (String scope: parameterValues) {
			for (String word: scope.split(" ")) {
				scopesRequested.add(word);
			}
		}
		return scopesRequested.stream()
				.map(scope -> clientConfig.getScopeMap().get(scope))
				.filter(scope -> scope != null)
				.collect(Collectors.toSet());
	}

	public Set<String> mapScopes(ClientExternalAuthenticationConfig.ClientExternalAuthConfig clientConfig,
			String[] parameterValues) {
		Set<String> scopesRequested = new HashSet<>();
		for (String scope: parameterValues) {
			for (String word: scope.split(" ")) {
				scopesRequested.add(word);
			}
		}
		return scopesRequested.stream()
				.map(scope -> clientConfig.getScopeMap().get(scope))
				.filter(scope -> scope != null)
				.collect(Collectors.toSet());
	}
}
