/*
 * Copyright 2020-2021 the original author or authors.
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
import java.util.List;
import java.util.stream.Collectors;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Consent screen integration tests for the sample Authorization Server
 *
 * @author Dmitriy Dubson
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class OAuth2AuthorizationServerConsentTests {
	@Autowired
	private WebClient webClient;

	@MockBean
	private OAuth2AuthorizationConsentService mockAuthorizationConsentService;

	private final String testConsentResultEndpoint = "http://127.0.0.1/login/oauth2/code/messaging-client-oidc";

	private final String authorizeEndpoint = UriComponentsBuilder
			.fromPath("/oauth2/authorize")
			.queryParam("response_type", "code")
			.queryParam("client_id", "messaging-client")
			.queryParam("scope", "openid message.read message.write")
			.queryParam("state", "state")
			.queryParam("redirect_uri", testConsentResultEndpoint)
			.toUriString();

	@Before
	public void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.webClient.getOptions().setRedirectEnabled(true);
		this.webClient.getCookieManager().clearCookies();
		when(mockAuthorizationConsentService.findById(any(), any())).thenReturn(null);
	}

	@Test
	@WithMockUser("user1")
	public void whenUserConsentsToAllScopesThenReturnAuthorizationCode() throws IOException {
		final HtmlPage consentPage = webClient.getPage(authorizeEndpoint);
		assertThat(consentPage.getTitleText()).isEqualTo("Consent required");

		List<HtmlCheckBoxInput> scopes = consentPage.querySelectorAll("input[name='scope']").stream()
				.map(scope -> (HtmlCheckBoxInput) scope).collect(Collectors.toList());
		for (HtmlCheckBoxInput scope : scopes) {
			scope.click();
		}

		assertThat(scopes.stream().map(DomElement::getId).collect(Collectors.toList()))
				.containsExactlyInAnyOrder("message.read", "message.write");
		assertThat(scopes.stream().allMatch(HtmlCheckBoxInput::isChecked)).isTrue();

		DomElement submitConsentButton = consentPage.querySelector("button[id='submit-consent']");
		this.webClient.getOptions().setRedirectEnabled(false);

		WebResponse approveConsentResponse = submitConsentButton.click().getWebResponse();
		assertThat(approveConsentResponse.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());
		String location = approveConsentResponse.getResponseHeaderValue("location");
		assertThat(location).startsWith(testConsentResultEndpoint);
		assertThat(location).contains("code=");
	}

	@Test
	@WithMockUser("user1")
	public void whenUserCancelsApprovingConsentThenReturnAnAccessDeniedError() throws IOException {
		final HtmlPage consentPage = webClient.getPage(authorizeEndpoint);
		assertThat(consentPage.getTitleText()).isEqualTo("Consent required");

		DomElement cancelConsentButton = consentPage.querySelector("button[id='cancel-consent']");
		this.webClient.getOptions().setRedirectEnabled(false);

		WebResponse cancelConsentResponse = cancelConsentButton.click().getWebResponse();
		assertThat(cancelConsentResponse.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());
		String location = cancelConsentResponse.getResponseHeaderValue("location");
		assertThat(location).contains("error=access_denied");
	}

}
