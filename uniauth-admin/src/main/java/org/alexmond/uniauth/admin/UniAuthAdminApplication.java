package org.alexmond.uniauth.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * A standalone console for administering the accounts behind a UniAuth deployment.
 *
 * <p>
 * It owns no user store, and it administers two services rather than one: the identity
 * provider, over its token-authenticated admin API, and the LDAP directory, over LDAP.
 * Those are the populations that exist independently of any application and outlive a
 * restart.
 *
 * <p>
 * It used to administer running UniAuth <em>applications</em> instead, over an admin API
 * the starter published. That API is gone — an authentication library has no business
 * exposing a write endpoint — and the accounts it reached lived in an application's
 * memory, so they did not survive a restart anyway. Managing the two real services is
 * both simpler and honest about what is being changed.
 *
 * <pre>
 * ./mvnw -pl uniauth-admin spring-boot:run
 * </pre>
 */
@SpringBootApplication
@EnableMethodSecurity
@EnableConfigurationProperties(ConsoleProperties.class)
public class UniAuthAdminApplication {

	public static void main(String[] args) {
		SpringApplication.run(UniAuthAdminApplication.class, args);
	}

}
