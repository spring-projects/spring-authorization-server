package org.springframework.authz.server.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.authz.server.filter.OAuthGrantBasedAuthenticationFilter;
import org.springframework.authz.server.filter.matcher.GrantTypeReqMatcher;
import org.springframework.authz.server.filter.validator.ClientCredentialRequestValidator;
import org.springframework.authz.server.filter.validator.RequestValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
public class AuthorizationFilterConfigurations {
	
	@Autowired
	RequestMatcher clientCredReqGrantMatcher;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	UserDetailsService clientCredentialsUserDetailsService;
	
	@Autowired
	AuthenticationManager clientCredentialsAuthenticationManager;
	
	@Autowired 
	AuthenticationFailureHandler clientCredentialAuthFailureHandler;
	
	@Autowired
	RequestValidator clientCredentialRequestValidator;
	
	@Bean
	public OAuthGrantBasedAuthenticationFilter clientCredentialsFilter() {
		
		OAuthGrantBasedAuthenticationFilter clientCredentialsFilter = new OAuthGrantBasedAuthenticationFilter();
		clientCredentialsFilter.setAuthenticationManager(clientCredentialsAuthenticationManager);
		clientCredentialsFilter.setAuthenticationFailureHandler(clientCredentialAuthFailureHandler); 
		clientCredentialsFilter.setReqConverter(new BasicAuthenticationConverter());
		clientCredentialsFilter.setReqGrantMatcher(clientCredReqGrantMatcher);
		clientCredentialsFilter.setReqValidator(clientCredentialRequestValidator);
		
		return clientCredentialsFilter;
		
	}
	
	@Bean
	public UserDetailsService clientCredentialsUserDetailsService() {
		InMemoryUserDetailsManager ccUserDetailsService = new InMemoryUserDetailsManager();
		ccUserDetailsService.createUser(new User("registered_client", passwordEncoder.encode("client_secret"), Collections.EMPTY_SET));
		return ccUserDetailsService;
	}
	
	@Bean
	public AuthenticationManager clientCredentialsAuthenticationManager()
	{
		DaoAuthenticationProvider ccAuthProvider = new DaoAuthenticationProvider();
		ccAuthProvider.setUserDetailsService(clientCredentialsUserDetailsService);
		ccAuthProvider.setPasswordEncoder(passwordEncoder);
		ProviderManager ccAuthManager = new ProviderManager(Arrays.asList(ccAuthProvider));
		return ccAuthManager;
	}
	
	
    @Bean
    public RequestMatcher clientCredReqGrantMatcher() {
    	
    	GrantTypeReqMatcher grantReqMatcher = new GrantTypeReqMatcher(new String[] {OAuthConstants.CLIENT_CRED_GRANT});
    	return grantReqMatcher;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public AuthenticationFailureHandler clientCredentialAuthFailureHandler() {
    	BasicAuthenticationEntryPoint basicAuthEntryPoint = new BasicAuthenticationEntryPoint();
    	AuthenticationEntryPointFailureHandler ccAuthFailureHandler = new AuthenticationEntryPointFailureHandler(basicAuthEntryPoint);
    	return ccAuthFailureHandler;
    }
    
    @Bean
    public RequestValidator clientCredentialRequestValidator() {
    	return new ClientCredentialRequestValidator();
    }

}
