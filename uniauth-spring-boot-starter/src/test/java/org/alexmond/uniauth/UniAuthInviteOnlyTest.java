package org.alexmond.uniauth;

import java.util.List;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code invite-only}, through the chain.
 *
 * <p>
 * Its own class because it needs its own property set — and because the assertion that
 * matters is about the <em>response</em>, not the record: a held principal gets a
 * redirect to the waiting page and a refused one gets 403, and only a real chain with
 * {@code PendingApprovalAccessDeniedHandler} on it can tell those apart.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(
		properties = { "uniauth.enabled=true", "uniauth.approval.enabled=true", "uniauth.approval.require-for=INTERNAL",
				"uniauth.approval.pending-page=/pending", "uniauth.approval.invitations.enabled=true",
				"uniauth.approval.invitations.invite-only=true", "uniauth.internal.enabled=true",
				"uniauth.internal.users[0].username=jane", "uniauth.internal.users[0].password={noop}s3cret",
				"uniauth.internal.users[1].username=bob", "uniauth.internal.users[1].password={noop}s3cret" })
class UniAuthInviteOnlyTest {

	private static final ApprovalKey JANE = new ApprovalKey("internal", "jane");

	private static final ApprovalKey BOB = new ApprovalKey("internal", "bob");

	@Autowired
	MockMvc mockMvc;

	@Autowired
	InvitationStore invitations;

	@Autowired
	ApprovalStore approvals;

	@BeforeEach
	void forgetEverything() {
		this.approvals.remove(JANE);
		this.approvals.remove(BOB);
	}

	@Test
	void anUninvitedPrincipalGetsAPlainRefusalRatherThanTheWaitingPage() throws Exception {
		HttpSession session = this.mockMvc.perform(formLogin("/login").user("bob").password("s3cret"))
			.andExpect(authenticated().withUsername("bob"))
			.andReturn()
			.getRequest()
			.getSession();

		// 403, not a redirect to /pending. Nobody is coming to approve them, and the
		// waiting page implies a queue somebody is reading.
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isForbidden());
		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.DENIED);
		assertThat(this.approvals.find(BOB)).get().extracting(ApprovalRecord::decidedBy).isEqualTo("invite-only");
	}

	@Test
	void anInvitedPrincipalIsStillAdmitted() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");
		this.mockMvc.perform(get("/invite/" + invitation.token().value())).andExpect(status().isOk());
		HttpSession session = this.mockMvc.perform(post("/invite/" + invitation.token().value()).with(csrf()))
			.andExpect(redirectedUrl("/login"))
			.andReturn()
			.getRequest()
			.getSession();
		HttpSession afterLogin = this.mockMvc
			.perform(post("/login").param("username", "jane")
				.param("password", "s3cret")
				.session((MockHttpSession) session)
				.with(csrf()))
			.andExpect(authenticated().withUsername("jane"))
			.andReturn()
			.getRequest()
			.getSession();

		this.mockMvc.perform(get("/").session((MockHttpSession) afterLogin)).andExpect(status().isOk());

		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void theChooserStaysReachableSoARefusedPersonCanSignOutAndTryTheRightLink() throws Exception {
		this.mockMvc.perform(get("/login")).andExpect(status().isOk());
	}

}
