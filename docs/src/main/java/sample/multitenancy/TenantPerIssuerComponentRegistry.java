/*
 * Copyright 2020-2024 the original author or authors.
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
package sample.multitenancy;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class TenantPerIssuerComponentRegistry {
	private final ConcurrentMap<String, Map<Class<?>, Object>> registry = new ConcurrentHashMap<>();

	public <T> void register(String tenantId, Class<T> componentClass, T component) {
		Assert.hasText(tenantId, "tenantId cannot be empty");
		Assert.notNull(componentClass, "componentClass cannot be null");
		Assert.notNull(component, "component cannot be null");
		Map<Class<?>, Object> components = this.registry.computeIfAbsent(tenantId, (key) -> new ConcurrentHashMap<>());
		components.put(componentClass, component);
	}

	@Nullable
	public <T> T get(Class<T> componentClass) {
		AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
		if (context == null || context.getIssuer() == null) {
			return null;
		}
		for (Map.Entry<String, Map<Class<?>, Object>> entry : this.registry.entrySet()) {
			if (context.getIssuer().endsWith(entry.getKey())) {
				return componentClass.cast(entry.getValue().get(componentClass));
			}
		}
		return null;
	}
}
