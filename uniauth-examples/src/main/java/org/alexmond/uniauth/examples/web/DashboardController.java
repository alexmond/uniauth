package org.alexmond.uniauth.examples.web;

import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.examples.session.SessionFacts;
import org.alexmond.uniauth.examples.session.SessionFactsResolver;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Pages that require a session. Reaching either of these while signed out lands you on
 * the starter's provider chooser.
 */
@Controller
public class DashboardController {

	private final AuthProviderRegistry registry;

	private final SessionFactsResolver resolver;

	public DashboardController(AuthProviderRegistry registry, SessionFactsResolver resolver) {
		this.registry = registry;
		this.resolver = resolver;
	}

	@GetMapping("/dashboard")
	public String dashboard(Authentication authentication, Model model) {
		SessionFacts facts = this.resolver.resolve(authentication);
		model.addAttribute("facts", facts);
		model.addAttribute("ports", this.registry.providers());
		model.addAttribute("live", facts.answeredBy());
		return "dashboard";
	}

	@GetMapping("/session")
	public String session(Authentication authentication, Model model) {
		model.addAttribute("facts", this.resolver.resolve(authentication));
		return "session";
	}

}
