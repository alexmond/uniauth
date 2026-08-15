package org.alexmond.uniauth.web;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Serves the provider-chooser login page.
 *
 * <p>
 * The mapping follows {@code uniauth.login-page}, so an app that moves the login path
 * does not also have to re-register a controller.
 */
@Controller
public class UniAuthLoginController {

	private final AuthProviderRegistry registry;

	private final UniAuthProperties properties;

	public UniAuthLoginController(AuthProviderRegistry registry, UniAuthProperties properties) {
		this.registry = registry;
		this.properties = properties;
	}

	@GetMapping("${uniauth.login-page:/login}")
	public String login(Model model, @RequestParam(required = false) String error,
			@RequestParam(required = false) String logout) {
		model.addAttribute("formProviders", registry.formProviders());
		model.addAttribute("redirectProviders", registry.redirectProviders());
		model.addAttribute("showForm", registry.hasFormProvider());
		model.addAttribute("noProviders", registry.isEmpty());
		model.addAttribute("loginPage", properties.getLoginPage());
		model.addAttribute("error", error != null);
		model.addAttribute("logout", logout != null);
		return "uniauth/login";
	}

}
