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
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.plugins.JavaLibraryPlugin;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.tasks.javadoc.Javadoc;

import org.springframework.gradle.management.SpringManagementConfigurationPlugin;

/**
 * Plugin to allow 'optional' and 'provided' dependency configurations
 *
 * As stated in the maven documentation, provided scope "is only available on the compilation and test classpath,
 * and is not transitive".
 *
 * This plugin creates two new configurations, and each one:
 * <ul>
 * <li>is a parent of the compile configuration</li>
 * <li>is not visible, not transitive</li>
 * <li>all dependencies are excluded from the default configuration</li>
 * </ul>
 *
 * @author Phillip Webb
 * @author Brian Clozel
 * @author Rob Winch
 * @author Steve Riesenberg
 *
 * @see <a href="https://www.gradle.org/docs/current/userguide/java_plugin.html#N121CF">Maven documentation</a>
 * @see <a href="https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope">Gradle configurations</a>
 * @see SpringPropDepsEclipsePlugin
 * @see SpringPropDepsIdeaPlugin
 */
public class SpringPropDepsPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getPlugins().withType(JavaPlugin.class, (javaPlugin) -> {
			Configuration provided = addConfiguration(project, "provided");
			Configuration optional = addConfiguration(project, "optional");

			Javadoc javadoc = (Javadoc) project.getTasks().getByName(JavaPlugin.JAVADOC_TASK_NAME);
			javadoc.setClasspath(javadoc.getClasspath().plus(provided).plus(optional));
		});
	}

	private Configuration addConfiguration(Project project, String name) {
		Configuration configuration = project.getConfigurations().create(name);
		configuration.extendsFrom(project.getConfigurations().getByName("implementation"));
		project.getPlugins().withType(JavaLibraryPlugin.class, (javaLibraryPlugin) ->
				configuration.extendsFrom(project.getConfigurations().getByName("api")));
		project.getPlugins().withType(SpringManagementConfigurationPlugin.class, (springManagementConfigurationPlugin) ->
				configuration.extendsFrom(project.getConfigurations().getByName("management")));

		JavaPluginExtension java = project.getExtensions().getByType(JavaPluginExtension.class);
		java.getSourceSets().all((sourceSet) -> {
			sourceSet.setCompileClasspath(sourceSet.getCompileClasspath().plus(configuration));
			sourceSet.setRuntimeClasspath(sourceSet.getRuntimeClasspath().plus(configuration));
		});

		return configuration;
	}
}
