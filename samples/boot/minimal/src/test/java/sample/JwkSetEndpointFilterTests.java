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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static sample.JwkSetEndpointFilter.DEFAULT_JWK_SET_URI;

@TestInstance(Lifecycle.PER_CLASS)
public class JwkSetEndpointFilterTests {
	private JWK jwk;
	private JWKSet jwkSet;
	private JwkSetEndpointFilter filter;
	private MockMvc mvc;

	@BeforeAll
	void setup() throws JOSEException {
		this.jwk = new RSAKeyGenerator(2048).keyID("endpoint-test").keyUse(KeyUse.SIGNATURE).generate();
		this.jwkSet = new JWKSet(this.jwk);
		this.filter = new JwkSetEndpointFilter(this.jwkSet);
		this.mvc = MockMvcBuilders.standaloneSetup(new HelloController()).addFilters(this.filter).alwaysDo(print()).build();
	}

	@Test
	void constructorWhenJWKSetNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwkSetEndpointFilter(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void doFilterWhenRequestMatchesThenProcess() throws Exception {
		String requestUri = DEFAULT_JWK_SET_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
	}

	@Test
	void doFilterWhenRequestDoesNotMatchThenContinueChain() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain, only()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	void requestWhenMatchesThenResponseContainsKeys() throws Exception {
		this.mvc.perform(get(DEFAULT_JWK_SET_URI))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.keys").isArray())
				.andExpect(jsonPath("$.keys").isNotEmpty())
				.andExpect(jsonPath("$.keys[0].kid").value(this.jwk.getKeyID()))
				.andExpect(jsonPath("$.keys[0].kty").value(this.jwk.getKeyType().toString()));
	}

	@Test
	void requestWhenDoesNotMatchThenResponseContainsOther() throws Exception {
		this.mvc.perform(get("/hello"))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(content().string(is("hello")));
	}

	@RestController
	static class HelloController {

		@RequestMapping("/hello")
		String hello() {
			return "hello";
		}
	}
}
