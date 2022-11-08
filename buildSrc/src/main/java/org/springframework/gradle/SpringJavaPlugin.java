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

package org.springframework.gradle;

import java.util.HashMap;
import java.util.Map;

import io.spring.javaformat.gradle.SpringJavaFormatPlugin;
import org.gradle.api.JavaVersion;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.GroovyPlugin;
import org.gradle.api.plugins.JavaPlugin;
import org.gradle.api.plugins.JavaPluginExtension;
import org.gradle.api.plugins.PluginManager;
import org.gradle.api.tasks.compile.CompileOptions;
import org.gradle.api.tasks.compile.JavaCompile;
import org.gradle.api.tasks.testing.Test;
import org.gradle.jvm.tasks.Jar;
import org.jetbrains.kotlin.gradle.plugin.KotlinPluginWrapper;

import org.springframework.gradle.checkstyle.SpringJavaCheckstylePlugin;
import org.springframework.gradle.docs.SpringJavadocOptionsPlugin;
import org.springframework.gradle.jacoco.SpringJacocoPlugin;
import org.springframework.gradle.management.SpringManagementConfigurationPlugin;
import org.springframework.gradle.maven.SpringRepositoryPlugin;
import org.springframework.gradle.propdeps.SpringPropDepsEclipsePlugin;
import org.springframework.gradle.propdeps.SpringPropDepsIdeaPlugin;
import org.springframework.gradle.properties.SpringCopyPropertiesPlugin;

/**
 * @author Steve Riesenberg
 */
public class SpringJavaPlugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		// Apply default plugins
		PluginManager pluginManager = project.getPluginManager();
		pluginManager.apply(JavaPlugin.class);
		pluginManager.apply(SpringManagementConfigurationPlugin.class);
		if (project.file("src/main/groovy").exists()
				|| project.file("src/test/groovy").exists()
				|| project.file("src/integration-test/groovy").exists()) {
			pluginManager.apply(GroovyPlugin.class);
		}
		if (project.file("src/main/kotlin").exists()
				|| project.file("src/test/kotlin").exists()
				|| project.file("src/integration-test/kotlin").exists()
				|| project.getBuildFile().getName().endsWith(".kts")) {
			pluginManager.apply(KotlinPluginWrapper.class);
		}
		pluginManager.apply(SpringRepositoryPlugin.class);
		pluginManager.apply(SpringPropDepsEclipsePlugin.class);
		pluginManager.apply(SpringPropDepsIdeaPlugin.class);
		pluginManager.apply(SpringJavadocOptionsPlugin.class);
		pluginManager.apply(SpringJavaFormatPlugin.class);
		pluginManager.apply(SpringJavaCheckstylePlugin.class);
		pluginManager.apply(SpringCopyPropertiesPlugin.class);
		pluginManager.apply(SpringJacocoPlugin.class);

		// Apply Java source compatibility version
		JavaPluginExtension java = project.getExtensions().getByType(JavaPluginExtension.class);
		java.setTargetCompatibility(JavaVersion.VERSION_17);

		// Configure Java tasks
		project.getTasks().withType(JavaCompile.class, (javaCompile) -> {
			CompileOptions options = javaCompile.getOptions();
			options.setEncoding("UTF-8");
			options.getCompilerArgs().add("-parameters");
			if (JavaVersion.current().isJava11Compatible()) {
				options.getRelease().set(17);
			}
		});
		project.getTasks().withType(Jar.class, (jar) -> jar.manifest((manifest) -> {
			Map<String, String> attributes = new HashMap<>();
			attributes.put("Created-By", String.format("%s (%s)", System.getProperty("java.version"), System.getProperty("java.specification.vendor")));
			attributes.put("Implementation-Title", project.getName());
			attributes.put("Implementation-Version", project.getVersion().toString());
			attributes.put("Automatic-Module-Name", project.getName().replace("-", "."));
			manifest.attributes(attributes);
		}));
		project.getTasks().withType(Test.class, (test) -> {
			test.useJUnitPlatform();
		});
	}
}
