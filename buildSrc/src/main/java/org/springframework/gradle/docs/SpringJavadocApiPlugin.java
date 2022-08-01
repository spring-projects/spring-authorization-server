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

package org.springframework.gradle.docs;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import io.spring.gradle.convention.SpringModulePlugin;
import org.gradle.api.Action;
import org.gradle.api.JavaVersion;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.tasks.SourceSet;
import org.gradle.api.tasks.javadoc.Javadoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Rob Winch
 * @author Steve Riesenberg
 */
public class SpringJavadocApiPlugin implements Plugin<Project> {
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private Set<Pattern> excludes = Collections.singleton(Pattern.compile("test"));

	@Override
	public void apply(Project project) {
		// Create task to generate aggregated docs
		Javadoc api = project.getTasks().create("api", Javadoc.class, (javadoc) -> {
			javadoc.setGroup("Documentation");
			javadoc.setDescription("Generates aggregated Javadoc API documentation.");
		});

		// Note: The following action cannot be a lambda, for groovy compatibility
		api.doLast(new Action<Task>() {
			@Override
			public void execute(Task task) {
				if (JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_17)) {
					project.copy((copy) -> copy.from(api.getDestinationDir())
							.into(api.getDestinationDir())
							.include("element-list")
							.rename("element-list", "package-list"));
				}
			}
		});

		Set<Project> subprojects = project.getRootProject().getSubprojects();
		for (Project subproject : subprojects) {
			addProject(api, subproject);
		}

		if (subprojects.isEmpty()) {
			addProject(api, project);
		}

		api.setMaxMemory("1024m");
		api.setDestinationDir(new File(project.getBuildDir(), "api"));
	}

	public void setExcludes(String... excludes) {
		if (excludes == null) {
			this.excludes = Collections.emptySet();
		}
		this.excludes = new HashSet<>(excludes.length);
		for (String exclude : excludes) {
			this.excludes.add(Pattern.compile(exclude));
		}
	}

	private void addProject(Javadoc api, Project project) {
		for (Pattern exclude : excludes) {
			if (exclude.matcher(project.getName()).matches()) {
				logger.info("Skipping {} because it is excluded by {}", project, exclude);
				return;
			}
		}
		logger.info("Try add sources for {}", project);
		project.getPlugins().withType(SpringModulePlugin.class, (plugin) -> {
			logger.info("Added sources for {}", project);

			JavaPluginExtension java = project.getExtensions().getByType(JavaPluginExtension.class);
			SourceSet mainSourceSet = java.getSourceSets().getByName("main");

			api.setSource(api.getSource().plus(mainSourceSet.getAllJava()));
			project.getTasks().withType(Javadoc.class).all((projectJavadoc) ->
					api.setClasspath(api.getClasspath().plus(projectJavadoc.getClasspath())));
		});
	}
}
