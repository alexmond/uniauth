package org.alexmond.uniauth.testapp;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
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

	}

}
