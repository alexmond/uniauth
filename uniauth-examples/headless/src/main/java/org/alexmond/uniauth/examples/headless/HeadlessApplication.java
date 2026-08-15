package org.alexmond.uniauth.examples.headless;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

/**
 * The API-first way to consume UniAuth: no templates, no server-rendered chooser.
 *
 * <p>
 * A single-page or mobile front end reads {@code GET /uniauth/providers} and renders its
 * own sign-in screen, then sends the user to whichever {@code loginUrl} they pick. The
 * starter still wires and runs every mechanism — only the presentation moves.
 *
 * <pre>
 * ./mvnw -Pdefault -pl uniauth-examples/headless spring-boot:run
 * curl localhost:8080/uniauth/providers        # what you can sign in with
 * curl -i localhost:8080/api/me                # 401, no redirect
 * </pre>
 */
@SpringBootApplication
public class HeadlessApplication {

	public static void main(String[] args) {
		SpringApplication.run(HeadlessApplication.class, args);
	}

	/**
	 * Turns the missing-session response from a redirect into a plain 401.
	 *
	 * <p>
	 * This one bean is the whole difference from the web app example. Without it an
	 * unauthenticated {@code fetch()} gets a 302 to an HTML login page, which a JSON
	 * client either follows into nonsense or reports as a confusing success. The starter
	 * uses any {@code AuthenticationEntryPoint} the application declares.
	 */
	@Bean
	AuthenticationEntryPoint unauthorizedEntryPoint() {
		return new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
	}

}
