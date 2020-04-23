package org.springframework.authz.server.config;

import org.springframework.authz.server.filter.OAuthGrantBasedAuthenticationFilter;
import org.springframework.authz.server.filter.matcher.GrantTypeReqMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private OAuthGrantBasedAuthenticationFilter clientCredentialsFilter;
	
	@Autowired
	private RequestMatcher clientCredReqGrantMatcher;
	
	@Override
    protected void configure(HttpSecurity http) throws Exception {
    	
    	http.authorizeRequests()
				.antMatchers("/token").permitAll();
    	
    	http.addFilterBefore(clientCredentialsFilter, BasicAuthenticationFilter.class);
    	//			BasicAuthenticationFilter.class);
    	
        /*http.authorizeRequests()
        		.antMatchers("/.well-known/openid-configuration").permitAll()
        		.antMatchers("/authorize").authenticated()
                .and()
                .formLogin();*/
        
        
    }
    
    
    
}
