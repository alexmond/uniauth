package org.alexmond.uniauth.examples;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The split this sample exists to demonstrate: the public pages render with no session,
 * the protected ones bounce to the chooser, and once signed in the dashboard names the
 * provider that actually answered.
 *
 * <p>
 * The signed-in cases carry the real session from the form post rather than a mock user,
 * so they exercise the provider resolution end to end — a mock principal would always
 * look like the internal store and the LDAP case would prove nothing.
 */
@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SamplePagesTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	ApprovalStore store;

	@Test
	void landingPageIsPublic() throws Exception {
		this.mockMvc.perform(get("/"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Four ways in")));
	}

	@Test
	void explainerPageIsPublic() throws Exception {
		this.mockMvc.perform(get("/how-it-works"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("two kinds of door")));
	}

	@Test
	void stylesheetIsPublic() throws Exception {
		this.mockMvc.perform(get("/css/uniauth.css")).andExpect(status().isOk());
	}

	@Test
	void loginPageUsesTheSampleReskin() throws Exception {
		this.mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Choose a door")));
	}

	@Test
	void dashboardRedirectsWhenSignedOut() throws Exception {
		this.mockMvc.perform(get("/dashboard")).andExpect(redirectedUrl("/login"));
	}

	@Test
	void sessionPageRedirectsWhenSignedOut() throws Exception {
		this.mockMvc.perform(get("/session")).andExpect(redirectedUrl("/login"));
	}

	@Test
	void internalAccountIsReportedAsInternal() throws Exception {
		HttpSession session = signIn("alice", "s3cret", "USER", "ADMIN");

		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("INTERNAL")));
	}

	@Test
	void directoryAccountIsReportedAsLdap() throws Exception {
		HttpSession session = signInApproved("bob", "bobspassword", "DEVELOPERS");

		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("LDAP")));
	}

	@Test
	void theDashboardShowsTheDirectoryEntryDistinguishedName() throws Exception {
		HttpSession session = signInApproved("bob", "bobspassword", "DEVELOPERS");

		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("uid=bob")));
	}

	/**
	 * The sample gates LDAP behind approval, so a directory account reaches the app only
	 * once someone has let it in. {@link ApprovalFlowTest} covers the gate itself; here
	 * it is just a precondition to get at the pages under test.
	 */
	@Test
	void aSuccessfulSignInLandsOnThePageThatReportsIt() throws Exception {
		// It used to land on "/", this application's PUBLIC overview, which says nothing
		// about having authenticated — so the one moment a user most wants confirmation
		// was the one page that offered none.
		this.mockMvc.perform(formLogin("/login").user("alice").password("s3cret"))
			.andExpect(redirectedUrl("/dashboard"));
	}

	@Test
	void theDashboardStatesThatAuthenticationSucceeded() throws Exception {
		HttpSession session = signIn("alice", "s3cret", "USER", "ADMIN");

		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) session))
			.andExpect(content().string(containsString("Authentication succeeded")));
	}

	@Test
	void theOldSessionUrlRedirectsRatherThan404s() throws Exception {
		// Its content moved onto the dashboard; the URL has been linked to.
		HttpSession session = signIn("alice", "s3cret", "USER", "ADMIN");

		this.mockMvc.perform(get("/session").session((MockHttpSession) session)).andExpect(redirectedUrl("/dashboard"));
	}

	@Test
	void theDashboardSaysWhoApprovedAHeldAccount() throws Exception {
		// bob comes through the gate, so the page reports the decision as well as the
		// authentication — "approved by alice" and "no approval needed" are different
		// facts, and a blank space states neither.
		HttpSession session = signInApproved("bob", "bobspassword", "DEVELOPERS");

		this.mockMvc.perform(get("/dashboard").session((MockHttpSession) session))
			.andExpect(content().string(containsString("Authenticating was not enough on its own")));
	}

	private HttpSession signInApproved(String username, String password, String... roles) throws Exception {
		HttpSession session = signIn(username, password, roles);
		ApprovalKey key = new ApprovalKey("ldap", username);
		this.store.recordPending(key, AuthProviderType.LDAP);
		this.store.decide(key, ApprovalStatus.APPROVED, "test");
		return session;
	}

	private HttpSession signIn(String username, String password, String... roles) throws Exception {
		return this.mockMvc.perform(formLogin("/login").user(username).password(password))
			.andExpect(authenticated().withUsername(username).withRoles(roles))
			.andReturn()
			.getRequest()
			.getSession();
	}

}
