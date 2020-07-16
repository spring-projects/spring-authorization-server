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
package org.springframework.security.crypto.keys;

import org.springframework.lang.Nullable;

import java.util.Set;

/**
 * Implementations of this interface are responsible for the management of {@link ManagedKey}(s),
 * e.g. {@code javax.crypto.SecretKey}, {@code java.security.PrivateKey}, {@code java.security.PublicKey}, etc.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see ManagedKey
 */
public interface KeyManager {

	/**
	 * Returns the {@link ManagedKey} identified by the provided {@code keyId},
	 * or {@code null} if not found.
	 *
	 * @param keyId the key ID
	 * @return the {@link ManagedKey}, or {@code null} if not found
	 */
	@Nullable
	ManagedKey findByKeyId(String keyId);

	/**
	 * Returns a {@code Set} of {@link ManagedKey}(s) having the provided key {@code algorithm},
	 * or an empty {@code Set} if not found.
	 *
	 * @param algorithm the key algorithm
	 * @return a {@code Set} of {@link ManagedKey}(s), or an empty {@code Set} if not found
	 */
	Set<ManagedKey> findByAlgorithm(String algorithm);

	/**
	 * Returns a {@code Set} of the {@link ManagedKey}(s).
	 *
	 * @return a {@code Set} of the {@link ManagedKey}(s)
	 */
	Set<ManagedKey> getKeys();

}
