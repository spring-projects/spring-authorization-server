package org.springframework.security.oauth2.server.authorization.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.RedirectStrategy;


/**
 * Tests for {@link OAuth2AuthorizationEndpointFilter}.
 *
 * @author Paurav Munshi
 */

public class OAuth2AuthorizationEndpointFilterTest {
	
	private OAuth2AuthorizationEndpointFilter filter;
	
	private RedirectStrategy authorizationRedirectStrategy = mock(RedirectStrategy.class);
	private Converter<HttpServletRequest, OAuth2AuthorizationRequest> authorizationConverter = mock(Converter.class);
	private OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
	private StringKeyGenerator codeGenerator = mock(StringKeyGenerator.class);
	private RegisteredClientRepository registeredClientRepository = mock(RegisteredClientRepository.class);
	
	@Before
	public void setUp() {
		filter = new OAuth2AuthorizationEndpointFilter();
		
		filter.setAuthorizationRequestConverter(authorizationConverter);
		filter.setAuthorizationService(authorizationService);
		filter.setCodeGenerator(codeGenerator);
		filter.setRegisteredClientRepository(registeredClientRepository);
		filter.setAuthorizationRedirectStrategy(authorizationRedirectStrategy);
	}

	@Test
	public void testSettersAreSettingProperValue() {
		OAuth2AuthorizationEndpointFilter blankFilter = new OAuth2AuthorizationEndpointFilter();
		
		assertThat(blankFilter.getAuthorizationRedirectStrategy()).isNull();
		assertThat(blankFilter.getAuthorizationRequestConverter()).isNull();
		assertThat(blankFilter.getAuthorizationService()).isNull();
		assertThat(blankFilter.getCodeGenerator()).isNull();
		assertThat(blankFilter.getRegisteredClientRepository()).isNull();
		
		blankFilter.setAuthorizationRequestConverter(authorizationConverter);
		blankFilter.setAuthorizationService(authorizationService);
		blankFilter.setCodeGenerator(codeGenerator);
		blankFilter.setRegisteredClientRepository(registeredClientRepository);
		blankFilter.setAuthorizationRedirectStrategy(authorizationRedirectStrategy);
		
		assertThat(blankFilter.getAuthorizationRedirectStrategy()).isEqualTo(authorizationRedirectStrategy);
		assertThat(blankFilter.getAuthorizationRequestConverter()).isEqualTo(authorizationConverter);
		assertThat(blankFilter.getAuthorizationService()).isEqualTo(authorizationService);
		assertThat(blankFilter.getCodeGenerator()).isEqualTo(codeGenerator);
		assertThat(blankFilter.getRegisteredClientRepository()).isEqualTo(registeredClientRepository);
	}

}
