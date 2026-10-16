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
	void theQueuePageAlsoShowsWhoIsAlreadyInAndWhatTheyMayDo() throws Exception {
		// Access granted is not access reviewed. Before list() the page could only show
		// who was waiting, so the people who already had access — and the roles they
		// hold — were invisible to the only screen an administrator ever opens (#10).
		HttpSession bob = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) bob));
		HttpSession alice = signIn("alice", "s3cret");
		this.mockMvc.perform(post("/approvals").session((MockHttpSession) alice)
			.with(csrf())
			.param("provider", "ldap")
			.param("principal", "bob")
			.param("outcome", "APPROVED")
			.param("roles", "FAMILY"));

		this.mockMvc.perform(get("/approvals").session((MockHttpSession) alice))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Who has access")))
			.andExpect(content().string(containsString("FAMILY")))
			// And out of the queue, which is the half the page could always show.
			.andExpect(content().string(containsString("Nobody is waiting")));
	}

	@Test
	void theAccessListOffersRevocationWithoutKnowingTheKeyByHeart() throws Exception {
		// The practical half of the gap: revoking took the exact ApprovalKey, which for
		// an OIDC login is an opaque subject claim nobody has memorised. Now the row
		// carries it.
		HttpSession bob = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) bob));
		HttpSession alice = signIn("alice", "s3cret");
		this.mockMvc.perform(post("/approvals").session((MockHttpSession) alice)
			.with(csrf())
			.param("provider", "ldap")
			.param("principal", "bob")
			.param("outcome", "APPROVED"));

		this.mockMvc.perform(get("/approvals").session((MockHttpSession) alice))
			.andExpect(content().string(containsString("value=\"revoke\"")));
	}

	@Test
	void somebodyRefusedIsStillOnThePageSoTheDecisionCanBeReconsidered() throws Exception {
		// A denied principal gets a plain 403 and never appears in the queue again, so
		// without enumeration the refusal was final by accident rather than by choice.
		HttpSession bob = signIn("bob", "bobspassword");
		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) bob));
		HttpSession alice = signIn("alice", "s3cret");
		this.mockMvc.perform(post("/approvals").session((MockHttpSession) alice)
			.with(csrf())
			.param("provider", "ldap")
			.param("principal", "bob")
			.param("outcome", "DENIED"));

		this.mockMvc.perform(get("/approvals").session((MockHttpSession) alice))
			.andExpect(content().string(containsString("Who was refused")));
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
