/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.gradle.maven;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin;
import org.jfrog.gradle.plugin.artifactory.ArtifactoryPlugin;
import org.jfrog.gradle.plugin.artifactory.dsl.ArtifactoryPluginConvention;

import org.springframework.gradle.ProjectUtils;

/**
 * @author Steve Riesenberg
 */
public class SpringArtifactoryPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		// Apply base plugin
		project.getPlugins().apply(ArtifactoryPlugin.class);

		// Apply artifactory repository configuration
		boolean isSnapshot = ProjectUtils.isSnapshot(project);
		boolean isMilestone = ProjectUtils.isMilestone(project);

		ArtifactoryPluginConvention artifactoryExtension = project.getExtensions().getByType(ArtifactoryPluginConvention.class);
		artifactoryExtension.publish((publish) -> {
			publish.setContextUrl("https://repo.spring.io");
			publish.repository((repository) -> {
				String repoKey = isSnapshot ? "libs-snapshot-local" : isMilestone ? "libs-milestone-local" : "libs-release-local";
				repository.setRepoKey(repoKey);
				if (project.hasProperty("artifactoryUsername")) {
					repository.setUsername((String) project.findProperty("artifactoryUsername"));
					repository.setPassword((String) project.findProperty("artifactoryPassword"));
				}
			});
			// Would fail if maven publish is not applied, i.e. in root project (SpringRootProjectPlugin)
			project.getPlugins().withType(MavenPublishPlugin.class, mavenPublish -> {
				publish.defaults((defaults) -> defaults.publications("mavenJava"));
			});
		});
	}
}
