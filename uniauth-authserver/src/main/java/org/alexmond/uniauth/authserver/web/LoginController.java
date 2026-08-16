package org.alexmond.uniauth.authserver.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The provider's own pages. Its own, because it is its own service.
 */
@Controller
public class LoginController {

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	/**
	 * Where a direct sign-in lands.
	 *
	 * <p>
	 * Inside an OAuth flow this is never reached — the entry point saved the authorize
	 * request and success resumes it, which is why {@code defaultSuccessUrl} is not
	 * {@code alwaysUse}. Signing in at the provider directly used to land on a 404, and a
	 * provider whose root 404s reads as a broken deployment to anyone checking it.
	 */
	@GetMapping("/")
	public String home(Authentication authentication, Model model) {
		// Passed in rather than read as #authentication in the template: that expression
		// comes from thymeleaf-extras-springsecurity, which this service does not depend
		// on. Without it the render fails AFTER the content type is set, and the failure
		// surfaces as "no converter for LinkedHashMap" — an error about the error page,
		// naming nothing that points here.
		model.addAttribute("name", (authentication != null) ? authentication.getName() : null);
		return "home";
	}

}
