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
package org.springframework.security.oauth2.server.authorization.context;

import org.springframework.security.oauth2.server.authorization.web.ProviderContextFilter;

/**
 * A holder of {@link ProviderContext} that associates it with the current thread using a {@code ThreadLocal}.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see ProviderContext
 * @see ProviderContextFilter
 */
public final class ProviderContextHolder {
	private static final ThreadLocal<ProviderContext> holder = new ThreadLocal<>();

	private ProviderContextHolder() {
	}

	/**
	 * Returns the {@link ProviderContext} bound to the current thread.
	 *
	 * @return the {@link ProviderContext}
	 */
	public static ProviderContext getProviderContext() {
		return holder.get();
	}

	/**
	 * Bind the given {@link ProviderContext} to the current thread.
	 *
	 * @param providerContext the {@link ProviderContext}
	 */
	public static void setProviderContext(ProviderContext providerContext) {
		if (providerContext == null) {
			resetProviderContext();
		} else {
			holder.set(providerContext);
		}
	}

	/**
	 * Reset the {@link ProviderContext} bound to the current thread.
	 */
	public static void resetProviderContext() {
		holder.remove();
	}

}
