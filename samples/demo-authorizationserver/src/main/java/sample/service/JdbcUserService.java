package sample.service;

import javax.sql.DataSource;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class JdbcUserService extends JdbcUserDetailsManager {

	public JdbcUserService(DataSource dataSource) {
		super(dataSource);
		// NOTE: The 'users' and 'authorities' tables must exist in the database.
//		if (!userExists("user1")) {
//			UserDetails user = User.withDefaultPasswordEncoder()
//					.username("user1")
//					.password("password")
//					.roles("USER")
//					.build();
//			createUser(user);
//		}
	}

}
