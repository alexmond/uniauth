package org.alexmond.uniauth.examples;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The demo hosts its own OAuth2 provider, so the OAUTH2 mechanism is demonstrable without
 * a Google project or an Entra tenant.
 *
 * <p>
 * The browser redirect dance is covered end to end elsewhere; what is pinned here is the
 * part that is easy to break silently — that the provider is a genuinely separate service
 * with its own accounts and its own login, rather than the application wearing a hat.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LocalOAuthProviderTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theProviderPublishesOpenIdDiscovery() throws Exception {
		this.mockMvc.perform(get("/.well-known/openid-configuration"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.authorization_endpoint").exists())
			.andExpect(jsonPath("$.token_endpoint").exists())
			.andExpect(jsonPath("$.jwks_uri").exists());
	}

	@Test
	void theChooserOffersItAsAnOidcProvider() throws Exception {
		this.mockMvc.perform(get("/uniauth/providers"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$[?(@.id == 'local')].type").value(org.hamcrest.Matchers.hasItem("OAUTH2")))
			// Unlike GitHub, this one is OpenID Connect — it issues an id_token.
			.andExpect(jsonPath("$[?(@.id == 'local')].oidc").value(org.hamcrest.Matchers.hasItem(true)))
			.andExpect(jsonPath("$[?(@.id == 'local')].loginUrl")
				.value(org.hamcrest.Matchers.hasItem("/oauth2/authorization/local")));
	}

	@Test
	void theProviderHasItsOwnLoginPageRatherThanTheApplicationChooser() throws Exception {
		this.mockMvc.perform(get("/oauth-provider/login"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Local OAuth provider")));
	}

	@Test
	void aProviderAccountIsNotAnApplicationAccount() throws Exception {
		// olivia exists at the provider only. Posting her credentials to the
		// application's
		// own form must fail — otherwise the two stores are not really separate.
		this.mockMvc.perform(formLogin("/login").user("olivia").password("oauth-pass"))
			.andExpect(org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers
				.unauthenticated());
	}

	@Test
	void anApplicationAccountIsNotAProviderAccount() throws Exception {
		// And the reverse: alice is an application account, unknown to the provider.
		this.mockMvc
			.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/oauth-provider/login")
				.param("username", "alice")
				.param("password", "s3cret")
				.with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
					.csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/oauth-provider/login?error"));
	}

	@Test
	void theTwoLoginsAreKeptInSeparateSessionEntries() throws Exception {
		// The design this asserts: the provider's chains use their own
		// SecurityContextRepository key. Sharing the default one would make an
		// application
		// session silently authorize OAuth flows, and a provider login silently sign you
		// in
		// to the application — neither of which happens between real, separate servers.
		HttpSession afterAppLogin = this.mockMvc.perform(formLogin("/login").user("alice").password("s3cret"))
			.andExpect(authenticated().withUsername("alice"))
			.andReturn()
			.getRequest()
			.getSession();

		assertThat(afterAppLogin.getAttribute("SPRING_SECURITY_CONTEXT")).isNotNull();
		assertThat(afterAppLogin.getAttribute("UNIAUTH_OAUTH_PROVIDER_CONTEXT")).isNull();

		HttpSession afterProviderLogin = this.mockMvc.perform(
				post("/oauth-provider/login").param("username", "olivia").param("password", "oauth-pass").with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andReturn()
			.getRequest()
			.getSession();

		assertThat(afterProviderLogin.getAttribute("UNIAUTH_OAUTH_PROVIDER_CONTEXT")).isNotNull();
		assertThat(afterProviderLogin.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
	}

}
