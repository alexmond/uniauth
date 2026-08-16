package org.alexmond.uniauth.admin;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The console has administrators of its own, signed in with UniAuth.
 *
 * <p>
 * They are a separate population from the accounts being administered — signing in here
 * grants nothing at the provider or in the directory, which is most of the reason to run
 * the console as its own process rather than a page inside one of them.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = { "console.provider.base-url=http://localhost:1", "console.provider.token=t",
		"console.directory.enabled=false" })
class ConsoleAccessTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theConsoleNeedsASignIn() throws Exception {
		this.mockMvc.perform(get("/")).andExpect(redirectedUrl("/login"));
	}

	@Test
	void anAdministratorSeesTheConfiguredStores() throws Exception {
		HttpSession session = signIn();

		this.mockMvc.perform(get("/").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("UniAuth provider")));
	}

	@Test
	void aStoreThatIsSwitchedOffIsNotOffered() throws Exception {
		HttpSession session = signIn();

		// The console lists what it can actually reach. Rendering a store nobody
		// configured, and letting it fail on the first click, is the bug this replaces.
		this.mockMvc.perform(get("/").session((MockHttpSession) session))
			.andExpect(content().string(org.hamcrest.Matchers.not(containsString("/stores/directory"))));
	}

	@Test
	void anUnreachableStoreRendersAMessageRatherThanBreakingThePage() throws Exception {
		// Port 1 is nothing; the console must still draw its page. An empty table with no
		// explanation reads as "this store is empty", which is a different and much more
		// alarming claim than "I could not ask".
		HttpSession session = signIn();

		this.mockMvc.perform(get("/stores/provider").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("not answering")));
	}

	@Test
	void anUnknownStoreGoesBackToTheList() throws Exception {
		HttpSession session = signIn();

		this.mockMvc.perform(get("/stores/nope").session((MockHttpSession) session)).andExpect(redirectedUrl("/"));
	}

	private HttpSession signIn() throws Exception {
		return this.mockMvc.perform(formLogin("/login").user("admin").password("admin"))
			.andExpect(authenticated().withUsername("admin"))
			.andReturn()
			.getRequest()
			.getSession();
	}

}
