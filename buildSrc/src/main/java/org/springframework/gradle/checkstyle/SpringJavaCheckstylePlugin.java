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

package org.springframework.gradle.checkstyle;

import java.io.File;

import javax.annotation.Nullable;

import io.spring.javaformat.gradle.tasks.CheckFormat;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.VersionCatalog;
import org.gradle.api.artifacts.VersionCatalogsExtension;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.quality.CheckstyleExtension;
import org.gradle.api.plugins.quality.CheckstylePlugin;

/**
 * Adds and configures Checkstyle plugin.
 *
 * @author Vedran Pavic
 * @author Steve Riesenberg
 */
public class SpringJavaCheckstylePlugin implements Plugin<Project> {
	private static final String CHECKSTYLE_DIR = "etc/checkstyle";
	private static final String SPRING_JAVAFORMAT_EXCLUDE_PACKAGES_PROPERTY = "springJavaformatExcludePackages";

	@Override
	public void apply(Project project) {
		project.getPlugins().withType(JavaPlugin.class, (javaPlugin) -> {
			File checkstyleDir = project.getRootProject().file(CHECKSTYLE_DIR);
			if (checkstyleDir.exists() && checkstyleDir.isDirectory()) {
				project.getPluginManager().apply(CheckstylePlugin.class);

				VersionCatalog versionCatalog = project.getRootProject().getExtensions().getByType(VersionCatalogsExtension.class).named("libs");

				project.getDependencies().add("checkstyle", versionCatalog.findLibrary("io-spring-javaformat-spring-javaformat-checkstyle").get());
				project.getDependencies().add("checkstyle", versionCatalog.findLibrary("io-spring-nohttp-nohttp-checkstyle").get());

				CheckstyleExtension checkstyle = project.getExtensions().getByType(CheckstyleExtension.class);
				checkstyle.getConfigDirectory().set(checkstyleDir);
				checkstyle.setToolVersion("8.34");
			}

			// Configure checkFormat task
			project.getTasks().withType(CheckFormat.class, (checkFormat) -> {
				// NOTE: See gradle.properties#springJavaformatExcludePackages for excluded packages
				String[] springJavaformatExcludePackages = getSpringJavaformatExcludePackages(project);
				if (springJavaformatExcludePackages != null) {
					checkFormat.exclude(springJavaformatExcludePackages);
				}
			});
		});
	}

	@Nullable
	private String[] getSpringJavaformatExcludePackages(Project project) {
		String springJavaformatExcludePackages = (String) project.findProperty(SPRING_JAVAFORMAT_EXCLUDE_PACKAGES_PROPERTY);
		return (springJavaformatExcludePackages != null) ? springJavaformatExcludePackages.split(" ") : null;
	}
}
