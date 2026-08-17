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

	/**
	 * Creates the controller.
	 * @param registry the single answer to what a user can sign in with right now
	 */
	public UniAuthProvidersController(AuthProviderRegistry registry) {
		this.registry = registry;
	}

	/**
	 * Serves the enabled providers as JSON, for a front end rendering its own chooser.
	 * @return every selectable provider, form-based ones first
	 */
	@GetMapping("${uniauth.providers-endpoint:/uniauth/providers}")
	/**
	 * Serves the enabled providers as JSON, for a front end rendering its own chooser.
	 * @return every selectable provider, form-based ones first
	 */
	public List<AuthProvider> providers() {
		return registry.providers();
	}

}
