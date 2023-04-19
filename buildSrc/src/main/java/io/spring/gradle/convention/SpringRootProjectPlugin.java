/*
 * Copyright 2002-2023 the original author or authors.
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

package io.spring.gradle.convention;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.BasePlugin;
import org.gradle.api.plugins.PluginManager;

import org.springframework.gradle.classpath.SpringCheckProhibitedDependenciesLifecyclePlugin;
import org.springframework.gradle.maven.SpringArtifactoryPlugin;
import org.springframework.gradle.maven.SpringNexusPlugin;
import org.springframework.gradle.nohttp.SpringNoHttpPlugin;
import org.springframework.gradle.sonarqube.SpringSonarQubePlugin;

/**
 * @author Steve Riesenberg
 */
public class SpringRootProjectPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		// Apply default plugins
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(BasePlugin.class);
		pluginManager.apply(SpringNoHttpPlugin.class);
		pluginManager.apply(SpringNexusPlugin.class);
		pluginManager.apply(SpringCheckProhibitedDependenciesLifecyclePlugin.class);
		pluginManager.apply(SpringArtifactoryPlugin.class);
		pluginManager.apply(SpringSonarQubePlugin.class);

		// Apply default repositories
		project.getRepositories().mavenCentral();
	}
}
