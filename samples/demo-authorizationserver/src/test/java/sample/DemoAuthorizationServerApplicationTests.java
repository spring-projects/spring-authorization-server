/*
 * Copyright 2020-2024 the original author or authors.
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

import java.io.IOException;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the sample Authorization Server.
 *
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"spring.profiles.include=test"})
@AutoConfigureMockMvc
public class DemoAuthorizationServerApplicationTests {
	private static final String REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc";

	private static final String AUTHORIZATION_REQUEST = UriComponentsBuilder
			.fromPath("/oauth2/authorize")
			.queryParam("response_type", "code")
			.queryParam("client_id", "messaging-client")
			.queryParam("scope", "openid")
			.queryParam("state", "some-state")
			.queryParam("redirect_uri", REDIRECT_URI)
			.toUriString();

	@Autowired
	private WebClient webClient;

	@BeforeEach
	public void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
		this.webClient.getOptions().setRedirectEnabled(true);
		this.webClient.getCookieManager().clearCookies();	// log out
	}

	@Test
	public void whenLoginSuccessfulThenDisplayBadRequestError() throws IOException {
		HtmlPage page = this.webClient.getPage("/");

		assertLoginPage(page);

		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		WebResponse signInResponse = signIn(page, "user1", "password").getWebResponse();

		assertThat(signInResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());	// there is no "default" index page
	}

	@Test
	public void whenLoginFailsThenDisplayBadCredentials() throws IOException {
		HtmlPage page = this.webClient.getPage("/");

		HtmlPage loginErrorPage = signIn(page, "user1", "wrong-password");

		HtmlElement alert = loginErrorPage.querySelector("div[role=\"alert\"]");
		assertThat(alert).isNotNull();
		assertThat(alert.asNormalizedText()).isEqualTo("Invalid username or password.");
	}

	@Test
	public void whenNotLoggedInAndRequestingTokenThenRedirectsToLogin() throws IOException {
		HtmlPage page = this.webClient.getPage(AUTHORIZATION_REQUEST);

		assertLoginPage(page);
	}

	@Test
	public void whenLoggingInAndRequestingTokenThenRedirectsToClientApplication() throws IOException {
		// Log in
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.webClient.getOptions().setRedirectEnabled(false);
		signIn(this.webClient.getPage("/login"), "user1", "password");

		// Request token
		WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());
		String location = response.getResponseHeaderValue("location");
		assertThat(location).startsWith(REDIRECT_URI);
		assertThat(location).contains("code=");
	}

	private static <P extends Page> P signIn(HtmlPage page, String username, String password) throws IOException {
		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		usernameInput.type(username);
		passwordInput.type(password);
		return signInButton.click();
	}

	private static void assertLoginPage(HtmlPage page) {
		assertThat(page.getUrl().toString()).endsWith("/login");

		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		assertThat(usernameInput).isNotNull();
		assertThat(passwordInput).isNotNull();
		assertThat(signInButton.getTextContent()).isEqualTo("Sign in");
	}

}
