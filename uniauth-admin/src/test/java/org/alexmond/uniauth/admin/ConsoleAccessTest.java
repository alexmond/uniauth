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
 * They are a separate population from the users being administered — an account here
 * grants nothing on any managed application, which is most of the reason to run the
 * console as its own process rather than a page inside one of them.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = { "console.targets[0].id=demo", "console.targets[0].name=Demo application",
		"console.targets[0].base-url=http://localhost:1", "console.targets[0].token=t" })
class ConsoleAccessTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void theConsoleNeedsASignIn() throws Exception {
		this.mockMvc.perform(get("/")).andExpect(redirectedUrl("/login"));
	}

	@Test
	void anAdministratorSeesTheManagedApplications() throws Exception {
		HttpSession session = signIn();

		this.mockMvc.perform(get("/").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Demo application")));
	}

	@Test
	void anUnreachableApplicationRendersAMessageRatherThanBreakingThePage() throws Exception {
		// Port 1 is nothing; the console must still draw its page. An administrator
		// discovering an application is down should see that, not a stack trace.
		HttpSession session = signIn();

		this.mockMvc.perform(get("/apps/demo").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("not answering")));
	}

	@Test
	void anUnknownApplicationGoesBackToTheList() throws Exception {
		HttpSession session = signIn();

		this.mockMvc.perform(get("/apps/nope").session((MockHttpSession) session)).andExpect(redirectedUrl("/"));
	}

	private HttpSession signIn() throws Exception {
		return this.mockMvc.perform(formLogin("/login").user("admin").password("console-pass"))
			.andExpect(authenticated().withUsername("admin"))
			.andReturn()
			.getRequest()
			.getSession();
	}

}
