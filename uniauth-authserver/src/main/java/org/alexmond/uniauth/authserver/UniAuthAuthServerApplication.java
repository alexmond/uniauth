package org.alexmond.uniauth.authserver;

import org.springframework.boot.SpringApplication;
import org.alexmond.uniauth.authserver.user.AuthServerProperties;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * A standalone OAuth2 / OpenID Connect provider.
 *
 * <p>
 * This used to live inside the demo web application, which made the demo both the
 * authorization server and its own client. That worked, but only by keeping the two
 * logins in separate session entries so neither could see the other — machinery that
 * existed purely to simulate the separation a second process gives for free. Running it
 * as its own service deletes the machinery and the caveat with it.
 *
 * <pre>
 * ./mvnw -pl uniauth-authserver spring-boot:run     # http://localhost:9000
 * </pre>
 */
@SpringBootApplication
@EnableConfigurationProperties(AuthServerProperties.class)
public class UniAuthAuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(UniAuthAuthServerApplication.class, args);
	}

}
