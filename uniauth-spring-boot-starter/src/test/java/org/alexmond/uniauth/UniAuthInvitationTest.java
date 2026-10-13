package org.alexmond.uniauth;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.HttpSession;
import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationRedeemedEvent;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.testapp.TestApplication;
import org.junit.jupiter.api.BeforeEach;
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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Invitations, end to end through the real filter chain.
 *
 * <p>
 * Driven this way because the claim happens in the authorization path and not in a
 * success handler: a test that stubbed the manager would prove nothing about the thing
 * most likely to be wrong. The internal store authenticates, since the mechanism is
 * irrelevant to redemption — the token is the proof, which is the whole reason this works
 * the same for SAML and LDAP as for OIDC.
 */
@SpringBootTest(classes = TestApplication.class)
@AutoConfigureMockMvc
@Import(UniAuthInvitationTest.Links.class)
@TestPropertySource(
		properties = { "uniauth.enabled=true", "uniauth.approval.enabled=true", "uniauth.approval.require-for=INTERNAL",
				"uniauth.approval.pending-page=/pending", "uniauth.approval.default-roles=USER",
				"uniauth.approval.invitations.enabled=true", "uniauth.internal.enabled=true",
				"uniauth.internal.users[0].username=jane", "uniauth.internal.users[0].password={noop}s3cret",
				"uniauth.internal.users[1].username=bob", "uniauth.internal.users[1].password={noop}s3cret" })
class UniAuthInvitationTest {

	private static final ApprovalKey JANE = new ApprovalKey("internal", "jane");

	private static final ApprovalKey BOB = new ApprovalKey("internal", "bob");

	@Autowired
	MockMvc mockMvc;

	@Autowired
	InvitationStore invitations;

	@Autowired
	ApprovalStore approvals;

	@Autowired
	Linker linker;

	@BeforeEach
	void forgetEverything() {
		this.approvals.remove(JANE);
		this.approvals.remove(BOB);
		this.linker.linked.clear();
		this.linker.refuse = false;
	}

	@Test
	void anInvitedPrincipalIsAdmittedOnTheFirstRequestWithNoPendingStep() {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");

		HttpSession session = openAndSignIn(invitation, "jane");

		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get()
			.extracting(ApprovalRecord::decidedBy)
			.isEqualTo("invitation:jane-record");
		assertThat(session).isNotNull();
	}

	@Test
	void theInvitationPathIsReachableBeforeAnybodyHasLoggedIn() throws Exception {
		// If it were not permitted, the gate would send it to the chooser and nobody
		// could ever accept — the invitation would silently do nothing.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		this.mockMvc.perform(get("/invite/" + invitation.token().value())).andExpect(status().isOk());
	}

	@Test
	void openingAnInvitationChangesNothingUntilItIsAccepted() throws Exception {
		// A GET cannot be CSRF-protected, so it must not touch the session. Otherwise
		// another site could plant its invitation in a visitor's and have their login
		// bound to a record of its choosing.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		this.mockMvc.perform(get("/invite/" + invitation.token().value())).andExpect(status().isOk());

		assertThat(this.invitations.find(invitation.token())).get()
			.satisfies((found) -> assertThat(found.usedBy()).isNull());
	}

	@Test
	void anApproversRefusalSurvivesARetryEvenWithAValidInvitationInTheSession() throws Exception {
		// The chain-level guard for the refusal-override: a claim whose listener threw
		// leaves exactly the PENDING record an approver acts on, and the retry must not
		// flip their decision back to APPROVED.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		this.linker.refuse = true;
		HttpSession session = openAndSignIn(invitation, "jane");
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.PENDING);

		this.approvals.decide(JANE, ApprovalStatus.DENIED, "admin", List.of());
		this.linker.refuse = false;

		// 403 rather than the waiting page, and still DENIED on the way out.
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isForbidden());
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.DENIED);
	}

	@Test
	void theInvitationsRolesAreOnThePrincipalOnTheVeryRequestThatGrantsThem() throws Exception {
		// The roles are created BY the authorization decision, so a filter placed before
		// AuthorizationFilter cannot carry them — it has already run. Without the manager
		// putting them on the context itself, the invited person lands on their first
		// hasRole-gated page and gets 403, and it then works on refresh. Measured on the
		// request rather than off the session, because that is what an application's own
		// rule sees.
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");

		HttpSession accepted = accept(invitation);
		HttpSession session = signIn(accepted, "jane");

		this.mockMvc.perform(get("/whoami").session((MockHttpSession) session))
			.andExpect(status().isOk())
			.andExpect(content().string(org.hamcrest.Matchers.containsString("ROLE_FAMILY")));
	}

	@Test
	void theRolesOnTheInvitationReachThePrincipal() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");
		HttpSession session = openAndSignIn(invitation, "jane");

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());

		assertThat(this.approvals.find(JANE)).get().extracting(ApprovalRecord::roles).isEqualTo(List.of("FAMILY"));
	}

	@Test
	void anInvitationWithNoRolesFallsBackToTheConfiguredDefault() {
		// Without this an admitted principal is refused by every hasRole() rule, which is
		// the bug #5 fixed arriving by a new route.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		openAndSignIn(invitation, "jane");

		assertThat(this.approvals.find(JANE)).get().extracting(ApprovalRecord::roles).isEqualTo(List.of("USER"));
	}

	@Test
	void theApplicationIsToldWhichLoginToLinkToWhichRecord() {
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		openAndSignIn(invitation, "jane");

		assertThat(this.linker.linked).singleElement().satisfies((event) -> {
			assertThat(event.key()).isEqualTo(JANE);
			assertThat(event.subjectRef()).isEqualTo("jane-record");
		});
	}

	@Test
	void theLinkSurvivesWithoutAnyListenerAtAll() {
		// Invitation.usedBy is why ApprovalRecord does not need a subjectRef field —
		// widening it would break every ApprovalStore implementor, as #5 already did
		// once.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");

		openAndSignIn(invitation, "jane");

		assertThat(this.invitations.find(invitation.token())).get().satisfies((claimed) -> {
			assertThat(claimed.usedBy()).isEqualTo(JANE);
			assertThat(claimed.subjectRef()).isEqualTo("jane-record");
		});
	}

	@Test
	void aSecondPersonCannotClaimTheSameInvitationAndIsHeldByTheOrdinaryGate() throws Exception {
		// Both accept while it is still open, which is the only way two people can be
		// holding the same token at once; whoever signs in first claims it. This is the
		// race redeem's compare-and-set exists for, and the loser has to fall through to
		// the ordinary gate rather than being admitted or shown an error.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		HttpSession bobsAcceptance = accept(invitation);
		openAndSignIn(invitation, "jane");

		HttpSession bobs = signIn(bobsAcceptance, "bob");

		this.mockMvc.perform(get("/").session((MockHttpSession) bobs)).andExpect(redirectedUrl("/pending"));
		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.PENDING);
	}

	@Test
	void openingAnInvitationSomebodyElseAlreadyUsedSaysSoRatherThanFailingQuietly() throws Exception {
		// The forwarded-link case: whoever opens it second is told why it will not work.
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		openAndSignIn(invitation, "jane");

		this.mockMvc.perform(get("/invite/" + invitation.token().value()))
			.andExpect(redirectedUrl("/login?invite=used"));
	}

	@Test
	void anExpiredInvitationIsRefusedAndAFreshOneForTheSameRecordWorks() throws Exception {
		Invitation stale = this.invitations.create("jane-record", Duration.ofMillis(1), List.of(), "admin");
		Thread.sleep(5);

		this.mockMvc.perform(get("/invite/" + stale.token().value())).andExpect(redirectedUrl("/login?invite=expired"));

		// Re-inviting mints a new invitation. The dead one stays dead: a used or expired
		// token is never reopened.
		Invitation fresh = this.invitations.create("jane-record", null, List.of(), "admin");
		openAndSignIn(fresh, "jane");
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void aRevokedInvitationIsRefused() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		this.invitations.revoke(invitation.token(), "admin");

		this.mockMvc.perform(get("/invite/" + invitation.token().value()))
			.andExpect(redirectedUrl("/login?invite=revoked"));
	}

	@Test
	void anUnusableTokenRedirectsToAPageTheStarterActuallyServes() throws Exception {
		// The regression guard for #11's shape. A redirect to an unserved page is how a
		// consumer got ERR_TOO_MANY_REDIRECTS.
		this.mockMvc.perform(get("/invite/nonsense")).andExpect(redirectedUrl("/login?invite=unknown"));

		this.mockMvc.perform(get("/login").param("invite", "unknown")).andExpect(status().isOk());
	}

	@Test
	void theInvitationRedirectCarriesTheContextPath() throws Exception {
		// Review Focus 5. An application mounted under a context path would otherwise
		// send
		// its visitors outside itself.
		this.mockMvc.perform(get("/app/invite/nonsense").contextPath("/app"))
			.andExpect(redirectedUrl("/app/login?invite=unknown"));
	}

	@Test
	void anAuthenticatedVisitorIsAdmittedOnlyAfterConfirming() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of(), "admin");
		HttpSession session = signIn("bob");
		// Bob is held by the ordinary gate at this point.
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));

		this.mockMvc.perform(get("/invite/" + invitation.token().value()).session((MockHttpSession) session))
			.andExpect(status().isOk());
		// Still not claimed: looking is not accepting.
		assertThat(this.invitations.find(invitation.token())).get()
			.satisfies((found) -> assertThat(found.usedBy()).isNull());

		this.mockMvc
			.perform(post("/invite/" + invitation.token().value()).session((MockHttpSession) session).with(csrf()))
			.andExpect(redirectedUrl("/"));
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());

		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.invitations.find(invitation.token())).get()
			.satisfies((found) -> assertThat(found.usedBy()).isEqualTo(BOB));
	}

	@Test
	void aListenerThatRefusesLeavesThePrincipalUnadmittedAndTheNextRequestRetries() throws Exception {
		Invitation invitation = this.invitations.create("jane-record", null, List.of("FAMILY"), "admin");
		this.linker.refuse = true;

		HttpSession session = openAndSignIn(invitation, "jane");

		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(redirectedUrl("/pending"));
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.PENDING);

		// Admitted-but-unlinked would be worse than this; and because the claim is keyed
		// to Jane, recovery is just the next request.
		this.linker.refuse = false;
		this.mockMvc.perform(get("/").session((MockHttpSession) session)).andExpect(status().isOk());
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	/** Walks the whole flow the way a person does: accept, sign in, land on a page. */
	private HttpSession openAndSignIn(Invitation invitation, String username) {
		try {
			HttpSession accepted = accept(invitation);
			HttpSession afterLogin = signIn(accepted, username);
			this.mockMvc.perform(get("/").session((MockHttpSession) afterLogin));
			return afterLogin;
		}
		catch (Exception failed) {
			throw new IllegalStateException(failed);
		}
	}

	/**
	 * Opens the invitation and accepts it, returning the session now carrying the token.
	 *
	 * <p>
	 * The GET only renders. The POST is what stashes, and it carries a CSRF token — a GET
	 * that stashed could be fired from another site.
	 * @param invitation the invitation to accept
	 * @return the session now holding the token
	 * @throws Exception if a request fails
	 */
	private HttpSession accept(Invitation invitation) throws Exception {
		this.mockMvc.perform(get("/invite/" + invitation.token().value())).andExpect(status().isOk());
		return this.mockMvc.perform(post("/invite/" + invitation.token().value()).with(csrf()))
			.andExpect(redirectedUrl("/login"))
			.andReturn()
			.getRequest()
			.getSession();
	}

	/**
	 * Signs in on an existing session.
	 *
	 * <p>
	 * Posted directly rather than through {@code formLogin()}, which cannot carry a
	 * session. Doing it this way also proves the stashed token survives Spring's
	 * session-fixation protection: a successful login changes the session id, and the
	 * token has to come across with the attributes.
	 * @param session the session to sign in on
	 * @param username who to sign in as
	 * @return the session after authentication
	 * @throws Exception if the login fails
	 */
	private HttpSession signIn(HttpSession session, String username) throws Exception {
		return this.mockMvc
			.perform(post("/login").param("username", username)
				.param("password", "s3cret")
				.session((MockHttpSession) session)
				.with(csrf()))
			.andExpect(authenticated().withUsername(username))
			.andReturn()
			.getRequest()
			.getSession();
	}

	private HttpSession signIn(String username) throws Exception {
		return this.mockMvc.perform(formLogin("/login").user(username).password("s3cret"))
			.andExpect(authenticated().withUsername(username))
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

	/** Stands in for the application doing the linking. */
	static class Linker {

		final List<InvitationRedeemedEvent> linked = new ArrayList<>();

		volatile boolean refuse;

		@EventListener
		void onRedeemed(InvitationRedeemedEvent event) {
			if (this.refuse) {
				throw new IllegalStateException("the application's database was down");
			}
			this.linked.add(event);
		}

	}

}
