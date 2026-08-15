package org.alexmond.uniauth.admin;

import org.alexmond.uniauth.admin.console.ManagedApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * A standalone console for administering users across one or more UniAuth applications.
 *
 * <p>
 * It deliberately owns no user store. Two of the three kinds a UniAuth application can
 * have — the internal store and a local OAuth provider's accounts — live inside that
 * application's memory and cannot be reached from another process, so the console asks
 * each application over its admin API instead of pretending to share state with it. The
 * obvious consequence is worth stating: restart a managed application and the accounts
 * this console created there are gone, because that is where they lived.
 *
 * <pre>
 * ./mvnw -pl uniauth-admin spring-boot:run
 * </pre>
 */
@SpringBootApplication
@EnableMethodSecurity
@EnableConfigurationProperties(ManagedApplication.class)
public class UniAuthAdminApplication {

	public static void main(String[] args) {
		SpringApplication.run(UniAuthAdminApplication.class, args);
	}

}
