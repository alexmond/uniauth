package org.alexmond.uniauth.web;

import org.alexmond.uniauth.provider.AuthProvider;
import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Exposes the enabled providers as JSON, so a single-page or mobile front end can render
 * its own chooser instead of using the bundled Thymeleaf page.
 */
@RestController
public class UniAuthProvidersController {

	private final AuthProviderRegistry registry;

	public UniAuthProvidersController(AuthProviderRegistry registry) {
		this.registry = registry;
	}

	@GetMapping("${uniauth.providers-endpoint:/uniauth/providers}")
	public List<AuthProvider> providers() {
		return registry.providers();
	}

}
