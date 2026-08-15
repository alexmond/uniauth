package org.alexmond.uniauth.examples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Runnable demonstration of the UniAuth starter.
 *
 * <p>
 * Starts with the internal store and an in-process LDAP directory already enabled, so a
 * working sign-in needs no external services. OAuth2 and SAML need a real identity
 * provider; the commented-out blocks in {@code application.yaml} show where their
 * configuration goes.
 *
 * <pre>
 * ./mvnw -Pdefault -DskipTests install                    # once — publishes the starter
 * ./mvnw -Pdefault -pl uniauth-examples spring-boot:run
 * </pre>
 *
 * The install step is not optional: {@code -pl} resolves the starter from the repository
 * rather than the reactor, and {@code -am} cannot stand in for it because it would run
 * {@code spring-boot:run} against the parent as well.
 */
@SpringBootApplication
public class UniAuthSampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(UniAuthSampleApplication.class, args);
	}

}
