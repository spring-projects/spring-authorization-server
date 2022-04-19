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

package org.springframework.gradle.maven;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

import org.springframework.gradle.ProjectUtils;

/**
 * @author Steve Riesenberg
 */
public class SpringPublishArtifactsPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getTasks().register("publishArtifacts", (publishArtifacts) -> {
			publishArtifacts.setGroup("Publishing");
			publishArtifacts.setDescription("Publish the artifacts to either Artifactory or Maven Central based on the version");
			if (ProjectUtils.isRelease(project)) {
				publishArtifacts.dependsOn("publishToOssrh");
			} else {
				publishArtifacts.dependsOn("artifactoryPublish");
			}
		});
	}
}
