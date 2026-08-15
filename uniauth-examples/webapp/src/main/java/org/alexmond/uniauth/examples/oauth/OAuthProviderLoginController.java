package org.alexmond.uniauth.examples.oauth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the local authorization server's own login page.
 *
 * <p>
 * Separate from {@code UniAuthLoginController}, which serves the application's provider
 * chooser. Two different services, two different pages — even though one process runs
 * both.
 */
@Controller
public class OAuthProviderLoginController {

	@GetMapping(AuthorizationServerConfiguration.LOGIN_PAGE)
	public String login() {
		return "oauth-provider-login";
	}

}
