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

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public class UserConsentRecord {

	private final String subject;
	private final String clientId;
	private final String authorizedScope;
	private final Instant consentGrantedTime;
	private final Duration lifetime;

	public UserConsentRecord(
			final String subject,
			final String clientId,
			final String authorizedScope) {
		this.subject = subject;
		this.clientId = clientId;
		this.authorizedScope = authorizedScope;
		// TODO: consentGrantedTime should be passed in so that it truly reflects when the consent was granted
		this.consentGrantedTime = Instant.now();
		// TODO:
		this.lifetime = Duration.ofDays(7);
	}

	public String getSubject() {
		return this.subject;
	}

	public String getClientId() {
		return this.clientId;
	}

	public String getAuthorizedScope() {
		return this.authorizedScope;
	}

	public boolean isValid() {
		return Instant.now().isBefore(this.consentGrantedTime.plus(this.lifetime));
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof UserConsentRecord)) return false;
		UserConsentRecord that = (UserConsentRecord) o;
		return Objects.equals(subject, that.subject)
				&& Objects.equals(clientId, that.clientId)
				&& Objects.equals(authorizedScope, that.authorizedScope)
				&& Objects.equals(consentGrantedTime, that.consentGrantedTime)
				&& Objects.equals(lifetime, that.lifetime);
	}

	@Override
	public int hashCode() {
		return Objects.hash(subject, clientId, authorizedScope, consentGrantedTime, lifetime);
	}
}
