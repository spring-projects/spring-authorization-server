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
package org.springframework.security.oauth2.core.context;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * A facility for holding information associated to a specific context.
 *
 * @author Joe Grandja
 * @since 0.1.0
 */
public interface Context {

	@Nullable
	<V> V get(Object key);

	@Nullable
	default <V> V get(Class<V> key) {
		Assert.notNull(key, "key cannot be null");
		V value = get((Object) key);
		return key.isInstance(value) ? value : null;
	}

	boolean hasKey(Object key);

}
