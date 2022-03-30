/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.gradle.propdeps;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.PluginManager;
import org.gradle.plugins.ide.idea.IdeaPlugin;
import org.gradle.plugins.ide.idea.model.IdeaModel;

/**
 * Plugin to allow optional and provided dependency configurations to work with the
 * standard gradle 'idea' plugin
 *
 * @author Phillip Webb
 * @author Brian Clozel
 * @author Steve Riesenberg
 * @link https://youtrack.jetbrains.com/issue/IDEA-107046
 * @link https://youtrack.jetbrains.com/issue/IDEA-117668
 */
public class SpringPropDepsIdeaPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(SpringPropDepsPlugin.class);
		pluginManager.apply(IdeaPlugin.class);

		IdeaModel ideaModel = project.getExtensions().getByType(IdeaModel.class);
		ideaModel.module((idea) -> {
			// IDEA internally deals with 4 scopes : COMPILE, TEST, PROVIDED, RUNTIME
			// but only PROVIDED seems to be picked up
			idea.getScopes().get("PROVIDED").get("plus").add(project.getConfigurations().getByName("provided"));
			idea.getScopes().get("PROVIDED").get("plus").add(project.getConfigurations().getByName("optional"));
		});
	}
}
