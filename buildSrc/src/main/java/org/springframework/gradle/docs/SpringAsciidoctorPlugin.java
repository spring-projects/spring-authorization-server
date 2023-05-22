/*
 * Copyright 2019-2020 the original author or authors.
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

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.asciidoctor.gradle.jvm.AbstractAsciidoctorTask;
import org.asciidoctor.gradle.jvm.AsciidoctorJExtension;
import org.asciidoctor.gradle.jvm.AsciidoctorJPlugin;
import org.asciidoctor.gradle.jvm.AsciidoctorTask;
import org.asciidoctor.gradle.jvm.pdf.AsciidoctorJPdfPlugin;
import org.gradle.api.Plugin;
import org.gradle.api.Project;

/**
 * Conventions that are applied in the presence of the {@link AsciidoctorJPlugin}. When
 * the plugin is applied:
 *
 * <ul>
 * <li>All warnings are made fatal.
 * <li>A task is created to resolve and unzip our documentation resources (CSS and
 * Javascript).
 * <li>For each {@link AsciidoctorTask} (HTML only):
 * <ul>
 * <li>A configuration named asciidoctorExtensions is used to add the
 * <a href="https://github.com/spring-io/spring-asciidoctor-extensions#block-switch">block
 * switch</a> extension
 * <li>{@code doctype} {@link AsciidoctorTask#options(Map) option} is configured.
 * <li>{@link AsciidoctorTask#attributes(Map) Attributes} are configured for syntax
 * highlighting, CSS styling, docinfo, etc.
 * </ul>
 * <li>For each {@link AbstractAsciidoctorTask} (HTML and PDF):
 * <ul>
 * <li>{@link AsciidoctorTask#attributes(Map) Attributes} are configured to enable
 * warnings for references to missing attributes, the year is added as @{code today-year},
 * etc
 * <li>{@link AbstractAsciidoctorTask#baseDirFollowsSourceDir() baseDirFollowsSourceDir()}
 * is enabled.
 * </ul>
 * </ul>
 *
 * @author Andy Wilkinson
 * @author Rob Winch
 * @author Steve Riesenberg
 */
public class SpringAsciidoctorPlugin implements Plugin<Project> {
	private static final String ASCIIDOCTORJ_VERSION = "2.4.3";
	private static final String EXTENSIONS_CONFIGURATION_NAME = "asciidoctorExtensions";

	@Override
	public void apply(Project project) {
		// Apply asciidoctor plugin
		project.getPluginManager().apply(AsciidoctorJPlugin.class);
		project.getPluginManager().apply(AsciidoctorJPdfPlugin.class);

		// Configure asciidoctor
		project.getPlugins().withType(AsciidoctorJPlugin.class, (asciidoctorPlugin) -> {
			configureDocumentationDependenciesRepository(project);
			makeAllWarningsFatal(project);
			upgradeAsciidoctorJVersion(project);
			createAsciidoctorExtensionsConfiguration(project);
			project.getTasks().withType(AbstractAsciidoctorTask.class, this::configureAsciidoctorExtension);
		});
	}

	private void configureDocumentationDependenciesRepository(Project project) {
		project.getRepositories().maven((mavenRepo) -> {
			mavenRepo.setUrl(URI.create("https://repo.spring.io/release"));
			mavenRepo.mavenContent((mavenContent) -> {
				mavenContent.includeGroup("io.spring.asciidoctor");
				mavenContent.includeGroup("io.spring.asciidoctor.backends");
				mavenContent.includeGroup("io.spring.docresources");
			});
		});
	}

	private void makeAllWarningsFatal(Project project) {
		project.getExtensions().getByType(AsciidoctorJExtension.class).fatalWarnings(".*");
	}

	private void upgradeAsciidoctorJVersion(Project project) {
		project.getExtensions().getByType(AsciidoctorJExtension.class).setVersion(ASCIIDOCTORJ_VERSION);
	}

	private void createAsciidoctorExtensionsConfiguration(Project project) {
		project.getConfigurations().create(EXTENSIONS_CONFIGURATION_NAME, (configuration) -> {
			project.getConfigurations().matching((candidate) -> "management".equals(candidate.getName()))
					.all(configuration::extendsFrom);
			configuration.getDependencies().add(project.getDependencies()
					.create("io.spring.asciidoctor.backends:spring-asciidoctor-backends:0.0.5"));
			configuration.getDependencies()
					.add(project.getDependencies().create("org.asciidoctor:asciidoctorj-pdf:1.5.3"));
		});
	}

	private void configureAsciidoctorExtension(AbstractAsciidoctorTask asciidoctorTask) {
		asciidoctorTask.configurations(EXTENSIONS_CONFIGURATION_NAME);
		configureCommonAttributes(asciidoctorTask);
		configureOptions(asciidoctorTask);
		asciidoctorTask.baseDirFollowsSourceDir();
		asciidoctorTask.resources((resourcesSpec) -> {
			resourcesSpec.from(asciidoctorTask.getSourceDir(), (resourcesSrcDirSpec) -> {
				// Not using intermediateWorkDir.
				// See https://github.com/asciidoctor/asciidoctor-gradle-plugin/issues/523
				resourcesSrcDirSpec.include("images/*.png", "css/**", "js/**", "**/*.java");
				// This exclusion is required to allow cacheability of :spring-authorization-server-docs:asciidoctor
				// The whole docs/src/docs/asciidoc folder is being passed as a task input
				resourcesSrcDirSpec.exclude("**/examples/build/**");
			});
		});
		if (asciidoctorTask instanceof AsciidoctorTask) {
			boolean pdf = asciidoctorTask.getName().toLowerCase().contains("pdf");
			String backend = (!pdf) ? "spring-html" : "spring-pdf";
			((AsciidoctorTask) asciidoctorTask).outputOptions((outputOptions) ->
					outputOptions.backends(backend));
		}
	}

	private void configureCommonAttributes(AbstractAsciidoctorTask asciidoctorTask) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put("attribute-missing", "warn");
		attributes.put("revnumber", null);
		asciidoctorTask.attributes(attributes);
	}

	private void configureOptions(AbstractAsciidoctorTask asciidoctorTask) {
		asciidoctorTask.options(Collections.singletonMap("doctype", "book"));
	}
}
