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

package org.springframework.gradle.sonarqube;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.sonarqube.gradle.SonarQubeExtension;
import org.sonarqube.gradle.SonarQubePlugin;

import org.springframework.gradle.ProjectUtils;

/**
 * @author Steve Riesenberg
 */
public class SpringSonarQubePlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		// Apply sonarqube plugin
		project.getPluginManager().apply(SonarQubePlugin.class);

		// Configure sonarqube
		SonarQubeExtension sonarqube = project.getExtensions().getByType(SonarQubeExtension.class);
		sonarqube.properties((properties) -> {
			String projectName = ProjectUtils.getProjectName(project);
			properties.property("sonar.java.coveragePlugin", "jacoco");
			properties.property("sonar.projectName", projectName);
			properties.property("sonar.jacoco.reportPath", project.getBuildDir().getName() + "/jacoco.exec");
			properties.property("sonar.links.homepage", "https://spring.io/" + projectName);
			properties.property("sonar.links.ci", "https://jenkins.spring.io/job/" + projectName + "/");
			properties.property("sonar.links.issue", "https://github.com/spring-projects/" + projectName + "/issues");
			properties.property("sonar.links.scm", "https://github.com/spring-projects/" + projectName);
			properties.property("sonar.links.scm_dev", "https://github.com/spring-projects/" + projectName + ".git");
		});
	}
}
