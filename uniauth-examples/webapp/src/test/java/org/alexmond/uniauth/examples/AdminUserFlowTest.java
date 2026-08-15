package org.alexmond.uniauth.examples;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Creating accounts in each of the three stores from one page.
 *
 * <p>
 * The assertion that matters is not that the form posts — it is that a user created
 * through it can then actually sign in, which is the only proof that an LDAP bind or an
 * in-memory createUser really happened.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AdminUserFlowTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theUsersPageNeedsAnAdministrator() throws Exception {
		// Every account in application.yaml is an admin, so a plain user has to be made
		// first — which the page under test is conveniently able to do.
		create("INTERNAL", "plain", "plain-pass", "USER");
		HttpSession user = signIn("plain", "plain-pass");

		this.mockMvc.perform(get("/admin/users").session((MockHttpSession) user)).andExpect(status().isForbidden());
		this.mockMvc.perform(get("/admin/users")).andExpect(redirectedUrl("/login"));
	}

	@Test
	void itListsAllThreeStores() throws Exception {
		HttpSession admin = signIn("alice", "s3cret");

		this.mockMvc.perform(get("/admin/users").session((MockHttpSession) admin))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Internal store")))
			.andExpect(content().string(containsString("Directory")))
			.andExpect(content().string(containsString("Local OAuth provider")));
	}

	@Test
	void anInternalUserCreatedHereCanSignIn() throws Exception {
		create("INTERNAL", "tessa", "tessa-pass", "USER");

		this.mockMvc.perform(formLogin("/login").user("tessa").password("tessa-pass"))
			.andExpect(authenticated().withUsername("tessa"));
	}

	@Test
	void aDirectoryUserCreatedHereCanSignIn() throws Exception {
		// The one store that is not a Java collection — this asserts a real LDAP bind
		// landed an entry the directory will authenticate against.
		create("LDAP", "dorothy", "dorothy-pass", "");

		this.mockMvc.perform(formLogin("/login").user("dorothy").password("dorothy-pass"))
			.andExpect(authenticated().withUsername("dorothy"));
	}

	@Test
	void anOauthUserCreatedHereBelongsToTheProviderNotTheApplication() throws Exception {
		create("OAUTH2", "otto", "otto-pass", "USER");

		// Signing in at the provider works...
		this.mockMvc
			.perform(
					post("/oauth-provider/login").param("username", "otto").param("password", "otto-pass").with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/"));

		// ...but the same credentials are not an application account.
		this.mockMvc.perform(formLogin("/login").user("otto").password("otto-pass"))
			.andExpect(org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers
				.unauthenticated());
	}

	@Test
	void aDuplicateNameIsReportedRatherThanSwallowed() throws Exception {
		HttpSession admin = signIn("alice", "s3cret");

		this.mockMvc
			.perform(post("/admin/users").session((MockHttpSession) admin)
				.with(csrf())
				.param("mechanism", "INTERNAL")
				.param("username", "alice")
				.param("password", "whatever")
				.param("roles", "USER"))
			.andExpect(redirectedUrl("/admin/users"));

		this.mockMvc.perform(get("/admin/users").session((MockHttpSession) admin))
			.andExpect(content().string(containsString("already an internal account")));
	}

	private void create(String mechanism, String username, String password, String roles) throws Exception {
		HttpSession admin = signIn("alice", "s3cret");
		this.mockMvc
			.perform(post("/admin/users").session((MockHttpSession) admin)
				.with(csrf())
				.param("mechanism", mechanism)
				.param("username", username)
				.param("password", password)
				.param("roles", roles))
			.andExpect(redirectedUrl("/admin/users"));
	}

	private HttpSession signIn(String username, String password) throws Exception {
		return this.mockMvc.perform(formLogin("/login").user(username).password(password))
			.andExpect(authenticated().withUsername(username))
			.andReturn()
			.getRequest()
			.getSession();
	}

}
