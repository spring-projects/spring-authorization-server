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
package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.io.Serializable;
import java.util.Collections;
import java.util.Set;

/**
 * @author Joe Grandja
 */
public class RegisteredClient implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private String id;
	private String clientId;
	private String clientSecret;
	private Set<ClientAuthenticationMethod> clientAuthenticationMethods = Collections.emptySet();
	private Set<AuthorizationGrantType> authorizationGrantTypes = Collections.emptySet();
	private Set<String> redirectUris = Collections.emptySet();
	private Set<String> scopes = Collections.emptySet();

}
