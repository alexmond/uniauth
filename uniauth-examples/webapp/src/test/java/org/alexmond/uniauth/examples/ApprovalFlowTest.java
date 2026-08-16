package org.alexmond.uniauth.examples;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
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
 * The whole approval story as a user would walk it: a directory account is held, an
 * administrator clears the queue, and the held session gets in without signing in again.
 */
@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class ApprovalFlowTest {

	private static final ApprovalKey BOB = new ApprovalKey("ldap", "bob");

	@Autowired
	MockMvc mockMvc;

	@Autowired
	ApprovalStore store;

	@BeforeEach
	void forgetPreviousDecisions() {
		this.store.remove(BOB);
	}

	@Test
	void aDirectoryAccountIsHeldAtTheWaitingPage() throws Exception {
		HttpSession bob = signIn("bob", "bobspassword");

		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) bob)).andExpect(redirectedUrl("/pending"));
		this.mockMvc.perform(get("/pending").session((MockHttpSession) bob))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Not connected")));
	}

	@Test
	void anInternalAdminIsNotHeldAndCanSeeTheQueue() throws Exception {
		HttpSession bob = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) bob));

		HttpSession alice = signIn("alice", "s3cret");

		this.mockMvc.perform(get("/approvals").session((MockHttpSession) alice))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("bob")));
	}

	@Test
	void approvingAdmitsTheHeldSessionWithoutASecondSignIn() throws Exception {
		HttpSession bob = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) bob)).andExpect(redirectedUrl("/pending"));

		HttpSession alice = signIn("alice", "s3cret");
		this.mockMvc
			.perform(post("/approvals").session((MockHttpSession) alice)
				.with(csrf())
				.param("provider", "ldap")
				.param("principal", "bob")
				.param("outcome", "APPROVED"))
			.andExpect(redirectedUrl("/approvals"));

		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) bob))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("LDAP")));
	}

	@Test
	void aHeldUserCannotReachTheQueueThemselves() throws Exception {
		HttpSession bob = signIn("bob", "bobspassword");

		// Held first by the approval gate; even once approved, ROLE_ADMIN still applies.
		this.mockMvc.perform(get("/approvals").session((MockHttpSession) bob)).andExpect(redirectedUrl("/pending"));
	}

	private HttpSession signIn(String username, String password) throws Exception {
		return this.mockMvc.perform(formLogin("/login").user(username).password(password))
			.andExpect(authenticated().withUsername(username))
			.andReturn()
			.getRequest()
			.getSession();
	}

}
