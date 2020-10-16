/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.security.oauth2.core.converter;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TODO
 * This class is temporary and will be removed after upgrading to Spring Security 5.5.0 GA.
 * These tests will probably be folded into tests for {@link ClaimConversionService}.
 *
 * Tests for {@link ObjectToSetStringConverter2}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class ObjectToSetStringConverter2Test {
	@Test
	@SuppressWarnings("unchecked")
	public void convertFromNullThenReturnNull() {
		ObjectToSetStringConverter2 converter = new ObjectToSetStringConverter2();
		Set<String> result = (Set<String>) converter.convert(null, null, null);
		assertThat(result).isNull();
	}

	@Test
	@SuppressWarnings("unchecked")
	public void convertFromStringThenReturnSet() {
		ObjectToSetStringConverter2 converter = new ObjectToSetStringConverter2();
		Set<String> result = (Set<String>) converter.convert("Hello", null, null);
		assertThat(result).containsExactly("Hello");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void convertFromSetThenReturnSet() {
		ObjectToSetStringConverter2 converter = new ObjectToSetStringConverter2();
		Set<String> result = (Set<String>) converter.convert(new HashSet<>(Arrays.asList("Hello", "world")), null, null);
		assertThat(result).containsExactlyInAnyOrder("Hello", "world");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void convertFromCollectionThenReturnSet() {
		ObjectToSetStringConverter2 converter = new ObjectToSetStringConverter2();
		Set<String> result = (Set<String>) converter.convert(Arrays.asList("Hello", "world"), null, null);
		assertThat(result).containsExactlyInAnyOrder("Hello", "world");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void convertFromEmptyCollectionThenReturnEmptySet() {
		ObjectToSetStringConverter2 converter = new ObjectToSetStringConverter2();
		Set<String> result = (Set<String>) converter.convert(Collections.emptyList(), null, null);
		assertThat(result).isEmpty();
	}
}
