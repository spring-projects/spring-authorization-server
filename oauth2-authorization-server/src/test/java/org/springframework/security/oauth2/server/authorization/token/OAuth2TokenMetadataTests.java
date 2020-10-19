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
package org.springframework.security.oauth2.server.authorization.token;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2TokenMetadata}.
 *
 * @author Joe Grandja
 */
public class OAuth2TokenMetadataTests {

	@Test
	public void metadataWhenNameNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2TokenMetadata.builder()
						.metadata(null, "value"))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void metadataWhenValueNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				OAuth2TokenMetadata.builder()
						.metadata("name", null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("value cannot be null");
	}

	@Test
	public void getMetadataWhenNameNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2TokenMetadata.builder().build().getMetadata(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("name cannot be empty");
	}

	@Test
	public void buildWhenDefaultThenDefaultsAreSet() {
		OAuth2TokenMetadata tokenMetadata = OAuth2TokenMetadata.builder().build();
		assertThat(tokenMetadata.getMetadata()).hasSize(1);
		assertThat(tokenMetadata.isInvalidated()).isFalse();
	}

	@Test
	public void buildWhenMetadataProvidedThenMetadataIsSet() {
		OAuth2TokenMetadata tokenMetadata = OAuth2TokenMetadata.builder()
				.invalidated()
				.metadata("name1", "value1")
				.metadata(metadata -> metadata.put("name2", "value2"))
				.build();
		assertThat(tokenMetadata.getMetadata()).hasSize(3);
		assertThat(tokenMetadata.isInvalidated()).isTrue();
		assertThat(tokenMetadata.<String>getMetadata("name1")).isEqualTo("value1");
		assertThat(tokenMetadata.<String>getMetadata("name2")).isEqualTo("value2");
	}
}
