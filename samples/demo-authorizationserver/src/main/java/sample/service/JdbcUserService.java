package sample.service;

import javax.sql.DataSource;

import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class JdbcUserService extends JdbcUserDetailsManager {

	public JdbcUserService(DataSource dataSource) {
		super(dataSource);
	}

}
