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

package io.spring.gradle.convention;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.file.DuplicatesStrategy;
import org.gradle.api.plugins.BasePlugin;
import org.gradle.api.plugins.PluginManager;
import org.gradle.api.tasks.TaskContainer;
import org.gradle.api.tasks.bundling.Zip;

import org.springframework.gradle.docs.SpringJavadocApiPlugin;
import org.springframework.gradle.docs.SpringJavadocOptionsPlugin;

/**
 * Aggregates asciidoc, javadoc, and deploying of the docs into a single plugin.
 *
 * @author Steve Riesenberg
 */
public class SpringDocsPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		// Apply default plugins
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(BasePlugin.class);
		// Note: Applying plugin via id since it requires groovy compilation
		pluginManager.apply("org.springframework.gradle.deploy-docs");
		pluginManager.apply(SpringJavadocApiPlugin.class);
		pluginManager.apply(SpringJavadocOptionsPlugin.class);

		// Add task to create documentation archive
		TaskContainer tasks = project.getTasks();
		Zip docsZip = tasks.create("docsZip", Zip.class, (zip) -> {
			zip.dependsOn(tasks.getByName("api"));
			zip.setGroup("Distribution");
			zip.getArchiveBaseName().set(project.getRootProject().getName());
			zip.getArchiveClassifier().set("docs");
			zip.setDescription("Builds -docs archive containing all " +
					"Docs for deployment at docs.spring.io");

			zip.from(tasks.getByName("api").getOutputs(), (copy) -> copy.into("api"));
			zip.into("docs");
			zip.setDuplicatesStrategy(DuplicatesStrategy.EXCLUDE);
		});

		// Add task to aggregate documentation
		Task docs = tasks.create("docs");
		docs.dependsOn(docsZip);
		docs.setGroup("Documentation");
		docs.setDescription("An aggregator task to generate all the documentation");

		// Wire docs task into the build
		tasks.getByName("assemble").dependsOn(docs);
	}
}
