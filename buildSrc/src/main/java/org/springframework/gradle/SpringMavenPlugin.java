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

package org.springframework.gradle;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.PluginManager;
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin;

import org.springframework.gradle.maven.SpringArtifactoryPlugin;
import org.springframework.gradle.maven.SpringMavenPublishingConventionsPlugin;
import org.springframework.gradle.maven.SpringPublishAllJavaComponentsPlugin;
import org.springframework.gradle.maven.SpringPublishArtifactsPlugin;
import org.springframework.gradle.maven.SpringPublishLocalPlugin;
import org.springframework.gradle.maven.SpringSigningPlugin;

/**
 * @author Steve Riesenberg
 */
public class SpringMavenPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		// Apply default plugins
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(MavenPublishPlugin.class);

		pluginManager.apply(SpringSigningPlugin.class);
		pluginManager.apply(SpringMavenPublishingConventionsPlugin.class);
		pluginManager.apply(SpringPublishAllJavaComponentsPlugin.class);
		pluginManager.apply(SpringPublishLocalPlugin.class);
		pluginManager.apply(SpringPublishArtifactsPlugin.class);
		pluginManager.apply(SpringArtifactoryPlugin.class);
	}
}
