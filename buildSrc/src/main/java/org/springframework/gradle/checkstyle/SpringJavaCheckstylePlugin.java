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
import java.util.Objects;

import javax.annotation.Nullable;

import io.spring.javaformat.gradle.tasks.CheckFormat;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
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
	private static final String SPRING_JAVAFORMAT_VERSION_PROPERTY = "springJavaformatVersion";
	private static final String DEFAULT_SPRING_JAVAFORMAT_VERSION = "0.0.31";
	private static final String NOHTTP_CHECKSTYLE_VERSION_PROPERTY = "nohttpCheckstyleVersion";
	private static final String DEFAULT_NOHTTP_CHECKSTYLE_VERSION = "0.0.11";
	private static final String CHECKSTYLE_TOOL_VERSION_PROPERTY = "checkstyleToolVersion";
	private static final String DEFAULT_CHECKSTYLE_TOOL_VERSION = "8.34";
	private static final String SPRING_JAVAFORMAT_EXCLUDE_PACKAGES_PROPERTY = "springJavaformatExcludePackages";

	@Override
	public void apply(Project project) {
		project.getPlugins().withType(JavaPlugin.class, (javaPlugin) -> {
			File checkstyleDir = project.getRootProject().file(CHECKSTYLE_DIR);
			if (checkstyleDir.exists() && checkstyleDir.isDirectory()) {
				project.getPluginManager().apply(CheckstylePlugin.class);

				// NOTE: See gradle.properties#springJavaformatVersion for actual version number
				project.getDependencies().add("checkstyle", "io.spring.javaformat:spring-javaformat-checkstyle:" + getSpringJavaformatVersion(project));
				// NOTE: See gradle.properties#nohttpCheckstyleVersion for actual version number
				project.getDependencies().add("checkstyle", "io.spring.nohttp:nohttp-checkstyle:" + getNohttpCheckstyleVersion(project));

				CheckstyleExtension checkstyle = project.getExtensions().getByType(CheckstyleExtension.class);
				checkstyle.getConfigDirectory().set(checkstyleDir);
				// NOTE: See gradle.properties#checkstyleToolVersion for actual version number
				checkstyle.setToolVersion(getCheckstyleToolVersion(project));
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

	private static String getSpringJavaformatVersion(Project project) {
		String springJavaformatVersion = DEFAULT_SPRING_JAVAFORMAT_VERSION;
		if (project.hasProperty(SPRING_JAVAFORMAT_VERSION_PROPERTY)) {
			springJavaformatVersion = Objects.requireNonNull(project.findProperty(SPRING_JAVAFORMAT_VERSION_PROPERTY)).toString();
		}
		return springJavaformatVersion;
	}

	private static String getNohttpCheckstyleVersion(Project project) {
		String nohttpCheckstyleVersion = DEFAULT_NOHTTP_CHECKSTYLE_VERSION;
		if (project.hasProperty(NOHTTP_CHECKSTYLE_VERSION_PROPERTY)) {
			nohttpCheckstyleVersion = Objects.requireNonNull(project.findProperty(NOHTTP_CHECKSTYLE_VERSION_PROPERTY)).toString();
		}
		return nohttpCheckstyleVersion;
	}

	private static String getCheckstyleToolVersion(Project project) {
		String checkstyleToolVersion = DEFAULT_CHECKSTYLE_TOOL_VERSION;
		if (project.hasProperty(CHECKSTYLE_TOOL_VERSION_PROPERTY)) {
			checkstyleToolVersion = Objects.requireNonNull(project.findProperty(CHECKSTYLE_TOOL_VERSION_PROPERTY)).toString();
		}
		return checkstyleToolVersion;
	}

	@Nullable
	private String[] getSpringJavaformatExcludePackages(Project project) {
		String springJavaformatExcludePackages = (String) project.findProperty(SPRING_JAVAFORMAT_EXCLUDE_PACKAGES_PROPERTY);
		return (springJavaformatExcludePackages != null) ? springJavaformatExcludePackages.split(" ") : null;
	}
}
