package org.alexmond.uniauth;

import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationRedeemedEvent;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.event.EventListener;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An invitation completed with a mechanism the approval gate does not cover.
 *
 * <p>
 * Its own class because the point is the <em>default</em>
 * {@code uniauth.approval.require-for}, which excludes INTERNAL — so this file sets no
 * {@code require-for} at all. Every other invitation test overrides it, which is exactly
 * how a whole configuration can pass its tests and still do nothing in the field: behind
 * the require-for check an invitation completed with an internal login claimed nothing,
 * published nothing and recorded no {@code usedBy}, while letting the person in, so
 * neither they nor whoever invited them had any sign it had failed.
 *
 * <p>
 * An invitation is not a gate. It says who a login belongs to, and the application wants
 * that link whichever mechanism answered.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthInvitationUngatedTest.Links.class)
@TestPropertySource(properties = { "uniauth.enabled=true", "uniauth.approval.enabled=true",
		"uniauth.approval.invitations.enabled=true", "uniauth.internal.enabled=true",
		"uniauth.internal.users[0].username=jane", "uniauth.internal.users[0].password={noop}s3cret" })
class UniAuthInvitationUngatedTest {

	private static final ApprovalKey JANE = new ApprovalKey("internal", "jane");

	@Autowired
	MockMvc mockMvc;

	@Autowired
	InvitationStore invitations;

	@Autowired
	ApprovalStore approvals;

	@Autowired
	Linker linker;

	@Test
	void theDefaultRequireForDoesNotCoverInternalAccounts() {
		// If this ever fails the rest of this class is testing nothing, so it is asserted
		// rather than assumed.
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
	}

	@Test
	void anInvitationIsStillClaimedAndLinked() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");

		HttpSession session = acceptAndSignIn(invitation);
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());

		assertThat(this.invitations.find(invitation.token())).get().satisfies((claimed) -> {
			assertThat(claimed.usedBy()).isEqualTo(JANE);
			assertThat(claimed.usedAt()).isNotNull();
		});
		assertThat(this.linker.linked).extracting(InvitationRedeemedEvent::subjectRef).containsExactly("jane-record");
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void andItsRolesReachTheRequestThatGrantedThem() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");

		HttpSession session = acceptAndSignIn(invitation);

		this.mockMvc.perform(get("/whoami").session((MockHttpSession) session))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("ROLE_FAMILY")));
	}

	private HttpSession acceptAndSignIn(Invitation invitation) throws Exception {
		this.mockMvc.perform(get("/invite/" + invitation.token().value())).andExpect(status().isOk());
		HttpSession accepted = this.mockMvc.perform(post("/invite/" + invitation.token().value()).with(csrf()))
			.andExpect(redirectedUrl("/login"))
			.andReturn()
			.getRequest()
			.getSession();
		return this.mockMvc
			.perform(post("/login").param("username", "jane")
				.param("password", "s3cret")
				.session((MockHttpSession) accepted)
				.with(csrf()))
			.andExpect(authenticated().withUsername("jane"))
			.andReturn()
			.getRequest()
			.getSession();
	}

	@TestConfiguration(proxyBeanMethods = false)
	static class Links {

		@Bean
		Linker linker() {
			return new Linker();
		}

	}

	static class Linker {

		final List<InvitationRedeemedEvent> linked = new ArrayList<>();

		@EventListener
		void onRedeemed(InvitationRedeemedEvent event) {
			this.linked.add(event);
		}

	}

}
