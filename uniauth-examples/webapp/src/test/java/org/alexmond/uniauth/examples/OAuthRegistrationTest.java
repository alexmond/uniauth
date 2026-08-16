package org.alexmond.uniauth.examples;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * What is left of the OAuth story in this application now that the provider is its own
 * service: a registration pointing at it, and nothing else.
 *
 * <p>
 * The provider's own behaviour — discovery, its login page, its accounts — is tested in
 * uniauth-authserver, which is where it lives. This application is a client, and a
 * client's job is to offer the button and honour the redirect.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OAuthRegistrationTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theChooserOffersTheProviderAsAnOidcOption() throws Exception {
		this.mockMvc.perform(get("/uniauth/providers"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[?(@.id == 'local')].type").value(hasItem("OAUTH2")))
			.andExpect(jsonPath("$[?(@.id == 'local')].oidc").value(hasItem(true)))
			.andExpect(jsonPath("$[?(@.id == 'local')].loginUrl").value(hasItem("/oauth2/authorization/local")));
	}

	@Test
	void thisApplicationNoLongerHostsAProvider() throws Exception {
		// The endpoints an authorization server would serve are simply not here; they are
		// on uniauth-authserver. Anonymous requests get the chooser like any other path.
		this.mockMvc.perform(get("/.well-known/openid-configuration")).andExpect(status().is3xxRedirection());
	}

}
