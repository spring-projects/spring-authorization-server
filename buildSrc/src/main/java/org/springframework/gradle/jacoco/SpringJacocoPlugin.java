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

package org.springframework.gradle.jacoco;

import java.util.Objects;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.testing.jacoco.plugins.JacocoPlugin;
import org.gradle.testing.jacoco.plugins.JacocoPluginExtension;

/**
 * Adds a version of jacoco to use and makes check depend on jacocoTestReport.
 *
 * @author Rob Winch
 * @author Steve Riesenberg
 */
public class SpringJacocoPlugin implements Plugin<Project> {
	private static final String JACOCO_TOOL_VERSION_PROPERTY = "jacocoToolVersion";
	private static final String DEFAULT_JACOCO_TOOL_VERSION = "0.8.7";

	@Override
	public void apply(Project project) {
		project.getPlugins().withType(JavaPlugin.class, (javaPlugin) -> {
			project.getPluginManager().apply(JacocoPlugin.class);
			project.getTasks().getByName("check").dependsOn(project.getTasks().getByName("jacocoTestReport"));

			JacocoPluginExtension jacoco = project.getExtensions().getByType(JacocoPluginExtension.class);
			// NOTE: See gradle.properties#jacocoToolVersion for actual version number
			jacoco.setToolVersion(getJacocoToolVersion(project));
		});
	}

	private static String getJacocoToolVersion(Project project) {
		String jacocoToolVersion = DEFAULT_JACOCO_TOOL_VERSION;
		if (project.hasProperty(JACOCO_TOOL_VERSION_PROPERTY)) {
			jacocoToolVersion = Objects.requireNonNull(project.findProperty(JACOCO_TOOL_VERSION_PROPERTY)).toString();
		}
		return jacocoToolVersion;
	}
}
