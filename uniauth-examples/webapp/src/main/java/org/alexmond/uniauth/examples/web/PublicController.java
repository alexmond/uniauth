package org.alexmond.uniauth.examples.web;

import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Pages anyone can read. These paths are opened up through {@code uniauth.public-paths}
 * in {@code application.yaml} rather than by replacing the filter chain; everything not
 * listed there needs a session.
 */
@Controller
public class PublicController {

	private final AuthProviderRegistry registry;

	public PublicController(AuthProviderRegistry registry) {
		this.registry = registry;
	}

	@GetMapping("/")
	public String index(Model model) {
		model.addAttribute("ports", registry.providers());
		model.addAttribute("live", null);
		return "index";
	}

	@GetMapping("/how-it-works")
	public String howItWorks(Model model) {
		model.addAttribute("ports", registry.providers());
		return "how-it-works";
	}

}
