/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.consent;

import org.springframework.util.Assert;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public class InMemoryUserConsentRepository implements UserConsentRepository {

	private final Set<UserConsentRecord> userConsentRecords = new HashSet<>();

	@Override
	public Set<UserConsentRecord> findBySubjectAndClientId(final String subject, final String clientId) {
		Assert.hasText(subject, "subject must have text");
		Assert.hasText(clientId, "clientId must have text");

		return this.userConsentRecords
				.stream()
				.filter(record -> subject.equals(record.getSubject()))
				.filter(record -> clientId.equals(record.getClientId()))
				.filter(UserConsentRecord::isValid)
				.collect(Collectors.toSet());
	}

	@Override
	public void saveAll(String subject, String clientId, Set<String> consentedScopes) {
		Assert.hasText(subject, "subject must have text");
		Assert.hasText(clientId, "clientId must have text");
		Assert.notNull(consentedScopes, "consentedScopes must not be null");

		Function<String, UserConsentRecord> mapScopeToConsent = (scope) -> new UserConsentRecord(
				subject,
				clientId,
				scope);

		// remove any older consent records
		this.revokeAll(subject, clientId, consentedScopes);
		this.userConsentRecords.addAll(consentedScopes.stream().map(mapScopeToConsent).collect(Collectors.toSet()));
	}

	@Override
	public void revokeAll(String subject, String clientId, Set<String> revokedScopes) {
		Assert.hasText(subject, "subject must have text");
		Assert.hasText(clientId, "clientId must have text");
		Assert.notNull(revokedScopes, "revokedScopes must not be null");

		revokedScopes.forEach(revokedScope -> this.revokeSingle(subject, clientId, revokedScope));
	}

	private void revokeSingle(String subject, String clientId, String revokedScope) {
		this.userConsentRecords
				.stream()
				.filter(record -> subject.equals(record.getSubject()))
				.filter(record -> clientId.equals(record.getClientId()))
				.filter(record -> revokedScope.equals(record.getAuthorizedScope()))
				.findFirst()
				.ifPresent(this.userConsentRecords::remove);
	}
}
