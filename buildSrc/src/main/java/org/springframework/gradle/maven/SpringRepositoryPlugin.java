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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.gradle.api.Plugin;
import org.gradle.api.Project;

import org.springframework.gradle.ProjectUtils;

/**
 * @author Steve Riesenberg
 */
public class SpringRepositoryPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		List<String> forceMavenRepositories = Collections.emptyList();
		if (project.hasProperty("forceMavenRepositories")) {
			forceMavenRepositories = Arrays.asList(((String) project.findProperty("forceMavenRepositories")).split(","));
		}

		boolean isImplicitSnapshotRepository = forceMavenRepositories.isEmpty() && ProjectUtils.isSnapshot(project);
		boolean isImplicitMilestoneRepository = forceMavenRepositories.isEmpty() && ProjectUtils.isMilestone(project);

		boolean isSnapshot = isImplicitSnapshotRepository || forceMavenRepositories.contains("snapshot");
		boolean isMilestone = isImplicitMilestoneRepository || forceMavenRepositories.contains("milestone");

		if (forceMavenRepositories.contains("local")) {
			project.getRepositories().mavenLocal();
		}
		project.getRepositories().mavenCentral();
		if (isSnapshot) {
			repository(project, "artifactory-snapshot", "https://repo.spring.io/snapshot/");
		}
		if (isSnapshot || isMilestone) {
			repository(project, "artifactory-milestone", "https://repo.spring.io/milestone/");
		}
		repository(project, "artifactory-release", "https://repo.spring.io/release/");
	}

	private void repository(Project project, String name, String url) {
		project.getRepositories().maven((repo) -> {
			repo.setName(name);
			if (project.hasProperty("artifactoryUsername")) {
				repo.credentials((credentials) -> {
					credentials.setUsername(Objects.requireNonNull(project.findProperty("artifactoryUsername")).toString());
					credentials.setPassword(Objects.requireNonNull(project.findProperty("artifactoryPassword")).toString());
				});
			}
			repo.setUrl(url);
		});
	}
}
