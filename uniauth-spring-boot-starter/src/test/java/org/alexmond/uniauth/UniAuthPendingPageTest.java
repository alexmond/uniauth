package org.alexmond.uniauth;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The waiting room a held principal is sent to.
 *
 * <p>
 * The gate redirected to {@code uniauth.approval.pending-page} and the starter served
 * nothing there, so a held principal got one redirect and a 404 — measured, not inferred:
 * {@code NoResourceFoundException: No static resource pending}. Nothing failed at startup
 * and nothing logged, and the only flow that reaches it is a real sign-in by somebody
 * actually pending, which no first manual run as an approved administrator performs
 * (#11).
 *
 * <p>
 * The page also has to offer a way out. Without one the only exit is the back button,
 * which returns to the provider and signs the same held account straight back in.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.internal.enabled=true",
		"uniauth.internal.users[0].username=held", "uniauth.internal.users[0].password={noop}pw",
		"uniauth.approval.enabled=true", "uniauth.approval.require-for=INTERNAL" })
class UniAuthPendingPageTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	void aHeldPrincipalIsSentToThePendingPageAndItIsServed() throws Exception {
		HttpSession held = signInAndBeHeld();

		this.mockMvc.perform(get("/pending").session((MockHttpSession) held)).andExpect(status().isOk());
	}

	@Test
	void thePageSaysWhatIsHappeningRatherThanThatSomethingWentWrong() throws Exception {
		String page = pendingPage(signInAndBeHeld());

		// A held principal authenticated successfully. Telling them access was denied
		// would describe a decision nobody has taken yet.
		assertThat(page).contains("waiting");
		assertThat(page).doesNotContain("Whitelabel");
	}

	@Test
	void thePageOffersAWayOutAndItIsAPost() throws Exception {
		// GET /logout never reaches LogoutFilter while CSRF is on — Spring's matcher is
		// POST-only — so a sign-out link falls through to the gate and bounces straight
		// back here. A form is the only exit that works.
		String page = pendingPage(signInAndBeHeld());

		assertThat(page).contains("method=\"post\"").contains("/logout");
		// And the token, or the POST this page exists to offer is refused with the 403
		// it was meant to avoid.
		assertThat(page).contains("_csrf");
	}

	private HttpSession signInAndBeHeld() throws Exception {
		HttpSession session = this.mockMvc.perform(formLogin("/login").user("held").password("pw"))
			.andReturn()
			.getRequest()
			.getSession();
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));
		return session;
	}

	private String pendingPage(HttpSession session) throws Exception {
		return this.mockMvc.perform(get("/pending").session((MockHttpSession) session))
			.andReturn()
			.getResponse()
			.getContentAsString();
	}

}
