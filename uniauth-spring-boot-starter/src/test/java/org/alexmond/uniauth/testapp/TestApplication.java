package org.alexmond.uniauth.testapp;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Minimal host application for the integration tests. The starter is picked up through
 * its {@code AutoConfiguration.imports} entry, exactly as it would be in a consuming app.
 *
 * <p>
 * It deliberately lives outside {@code org.alexmond.uniauth} so that its component scan
 * cannot reach the starter's own {@code @Controller} classes. Were it to sit at the
 * starter's root package, scanning would register those controllers directly and quietly
 * bypass both the auto-configuration's {@code @Bean} methods and the
 * {@code uniauth.enabled} guard.
 */
@SpringBootApplication
public class TestApplication {

	@RestController
	static class SecuredController {

		@GetMapping("/")
		String home() {
			return "home";
		}

		/**
		 * Echoes the authorities the <em>current request</em> carries.
		 *
		 * <p>
		 * Reading them off the session afterwards answers a different question: a change
		 * made to the context mid-request is not persisted by default, so the session can
		 * lack an authority the request itself had. What an application's
		 * {@code hasRole(...)} rule sees is this.
		 * @return the authorities, comma separated
		 */
		@GetMapping("/whoami")
		String whoami() {
			org.springframework.security.core.Authentication current = org.springframework.security.core.context.SecurityContextHolder
				.getContext()
				.getAuthentication();
			return current.getAuthorities()
				.stream()
				.map(org.springframework.security.core.GrantedAuthority::getAuthority)
				.sorted()
				.collect(java.util.stream.Collectors.joining(","));
		}

		/**
		 * An application's own write endpoint, called by a front end that holds no
		 * server-rendered form and therefore carries no session CSRF token.
		 *
		 * <p>
		 * This is the shape of #12: enabling UniAuth turned such a POST from 200 into
		 * 403, because the starter owns the chain and never configured CSRF, and no
		 * extension point reached {@code HttpSecurity} to say otherwise.
		 * @return anything; only the status is under test
		 */
		@PostMapping("/api/feedback")
		String feedback() {
			return "thanks";
		}

	}

}
