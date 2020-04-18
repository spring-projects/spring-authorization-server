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

package sample;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static sample.JwkSetEndpointFilter.WELL_KNOWN_JWK_URIS;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

@TestInstance(Lifecycle.PER_CLASS)
public class JwkSetEndpointFilterTest {

	private MockMvc mvc;
	private JWKSet jwkSet;
	private JWK jwk;
	private JwkSetEndpointFilter filter;

	@BeforeAll
	void setup() throws JOSEException {
		this.jwk = new RSAKeyGenerator(2048).keyID("endpoint-test").keyUse(KeyUse.SIGNATURE).generate();
		this.jwkSet = new JWKSet(jwk);
		this.filter = new JwkSetEndpointFilter(jwkSet);
		this.mvc = MockMvcBuilders.standaloneSetup(new FakeController()).addFilters(filter).alwaysDo(print()).build();
	}

	@Test
	void constructorWhenJsonWebKeySetIsNullThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwkSetEndpointFilter(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void doFilterWhenPathMatches() throws Exception {
		String requestUri = WELL_KNOWN_JWK_URIS;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain, never()).doFilter(Mockito.any(HttpServletRequest.class),
				Mockito.any(HttpServletResponse.class));
	}

	@Test
	void doFilterWhenPathDoesNotMatch() throws Exception {
		String requestUri = "/stuff/" + WELL_KNOWN_JWK_URIS;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain, only()).doFilter(Mockito.any(HttpServletRequest.class),
				Mockito.any(HttpServletResponse.class));
	}

	@Test
	void testResponseIfRequestMatches() throws Exception {
		mvc.perform(get(WELL_KNOWN_JWK_URIS)).andDo(print()).andExpect(status().isOk())
				.andExpect(jsonPath("$.keys").isArray()).andExpect(jsonPath("$.keys").isNotEmpty())
				.andExpect(jsonPath("$.keys[0].kid").value(jwk.getKeyID()))
				.andExpect(jsonPath("$.keys[0].kty").value(jwk.getKeyType().toString()));
	}

	@Test
	void testResponseIfNotRequestMatches() throws Exception {
		mvc.perform(get("/fake")).andDo(print()).andExpect(status().isOk())
				.andExpect(content().string(is("fake")));
	}

	@RestController
	class FakeController {

		@RequestMapping("/fake")
		public String hello() {
			return "fake";
		}
	}
}
