package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class H2ConsoleSecurityConfig {

	// @formatter:off
	@Bean
	@Order(1)
	public SecurityFilterChain h2consoleSecurityFilterChain(HttpSecurity http) throws Exception {
		http
				.securityMatcher("/h2-console/**")
				.authorizeHttpRequests((authorize) ->
						authorize.anyRequest().permitAll()
				)
				.headers((headers) ->
						headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
				)
				.csrf(AbstractHttpConfigurer::disable);

		return http.build();
	}
	// @formatter:on

}
