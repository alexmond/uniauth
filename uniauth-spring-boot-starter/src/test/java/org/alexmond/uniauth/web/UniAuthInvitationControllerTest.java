package org.alexmond.uniauth.web;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InMemoryInvitationStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.Invitations;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The endpoint, driven directly.
 *
 * <p>
 * The chain-level proof — that the path is permitted and reachable before anybody has
 * logged in — lives in {@code UniAuthInvitationTest}. What is worth testing here is the
 * branching, because there are six outcomes and they turn on two independent things: who
 * is asking, and what state the invitation is in.
 */
class UniAuthInvitationControllerTest {

	private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

	private InMemoryInvitationStore store;

	private UniAuthProperties properties;

	private UniAuthInvitationController controller;

	@BeforeEach
	void freshController() {
		this.store = new InMemoryInvitationStore(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(14));
		this.properties = new UniAuthProperties();
		this.controller = new UniAuthInvitationController(this.store, this.properties,
				Clock.fixed(NOW, ZoneOffset.UTC));
	}

	@Test
	void aGetNeverStashesSoAnInvitationCannotBeFixedIntoSomebodyElsesSession() {
		// Login-CSRF, and the reason a GET here may not touch the session. A GET cannot
		// be CSRF-protected, so anything that stashed on one could be fired from an
		// attacker's page — an img tag, an iframe, a link — planting their invitation in
		// a victim's session. The victim then signs in with their own account and the
		// gate binds it to the record the attacker's invitation names, without ever
		// showing the confirmation page that exists to make precisely that deliberate.
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();

		this.controller.open(invitation.token().value(), null, request, new ExtendedModelMap());

		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void anAnonymousVisitorGetsTheAcceptPageRatherThanBeingStashedSilently() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		Model model = new ExtendedModelMap();

		String view = this.controller.open(invitation.token().value(), null, new MockHttpServletRequest(), model);

		assertThat(view).isEqualTo("uniauth/invite");
		// Null rather than absent, so the page can say "sign in to accept" instead of
		// naming an account nobody is signed in to.
		assertThat(model.getAttribute("signedInAs")).isNull();
		assertThat(model.getAttribute("token")).isEqualTo(invitation.token().value());
	}

	@Test
	void anUnknownTokenGoesToTheChooserWithAReasonRatherThanAPageTheStarterDoesNotServe() {
		// Review Focus 2, and the shape of #11: a redirect to an unserved page gave a
		// consumer ERR_TOO_MANY_REDIRECTS. The chooser is already served.
		MockHttpServletRequest request = new MockHttpServletRequest();

		String view = this.controller.open("not-a-real-token", null, request, new ExtendedModelMap());

		assertThat(view).isEqualTo("redirect:/login?invite=unknown");
		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void tokenShapedJunkIsStillJustUnknown() {
		// Review Focus 2. A scanner, a truncated copy-paste, a blank segment — none of
		// these may become a 500 or escape the path.
		for (String junk : List.of("../../etc/passwd", "%00", "  ", "a".repeat(10_000), "<script>")) {
			assertThat(this.controller.open(junk, null, new MockHttpServletRequest(), new ExtendedModelMap()))
				.isEqualTo("redirect:/login?invite=unknown");
		}
	}

	@Test
	void aUsedInvitationSaysSo() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(invitation.token(), new ApprovalKey("google", "someone"));

		assertThat(this.controller.open(invitation.token().value(), null, new MockHttpServletRequest(),
				new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=used");
	}

	@Test
	void anExpiredInvitationSaysSo() {
		Invitation invitation = this.store.create("jane", Duration.ofSeconds(1), List.of(), "admin");
		UniAuthInvitationController later = new UniAuthInvitationController(this.store, this.properties,
				Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC));

		assertThat(later.open(invitation.token().value(), null, new MockHttpServletRequest(), new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=expired");
	}

	@Test
	void aRevokedInvitationSaysRevokedRatherThanUnknown() {
		// Somebody whose invitation was withdrawn is in a different position from
		// somebody
		// holding a typo, and they will go and ask the person who withdrew it.
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.revoke(invitation.token(), "admin");

		assertThat(this.controller.open(invitation.token().value(), null, new MockHttpServletRequest(),
				new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=revoked");
	}

	@Test
	void theChooserPathIsWhicheverTheApplicationConfigured() {
		this.properties.setLoginPage("/sign-in");

		assertThat(this.controller.open("nope", null, new MockHttpServletRequest(), new ExtendedModelMap()))
			.isEqualTo("redirect:/sign-in?invite=unknown");
	}

	@Test
	void anAuthenticatedVisitorGetsAConfirmationPageRatherThanBeingClaimedSilently() {
		// The URL is the credential, so whoever holds it gets Jane's record. That cannot
		// be designed away; what it can be is deliberate rather than accidental.
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		Model model = new ExtendedModelMap();

		String view = this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(), model);

		assertThat(view).isEqualTo("uniauth/invite");
		assertThat(model.getAttribute("signedInAs")).isEqualTo("bob@example.com");
		assertThat(model.getAttribute("token")).isEqualTo(invitation.token().value());
		assertThat(model.getAttribute("invitePath")).isEqualTo("/invite/{token}");
	}

	@Test
	void theConfirmationPageDoesNotRevealWhoTheInvitationNames() {
		// The visitor may not be the invited person. The subjectRef is the application's
		// own identifier for somebody else, and the page does not need it to do its job.
		Invitation invitation = this.store.create("jane-record-4417", null, List.of(), "admin");
		Model model = new ExtendedModelMap();

		this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(), model);

		assertThat(model.asMap().values())
			.noneSatisfy((value) -> assertThat(String.valueOf(value)).contains("jane-record-4417"));
	}

	@Test
	void theGetDoesNotClaimAnythingEvenForAnAuthenticatedVisitor() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");

		this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(), new ExtendedModelMap());

		assertThat(this.store.find(invitation.token())).get().satisfies((found) -> assertThat(found.usedBy()).isNull());
	}

	@Test
	void anAuthenticatedVisitorWithADeadInvitationIsSentToTheChooserWithTheReason() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.revoke(invitation.token(), "admin");

		assertThat(this.controller.open(invitation.token().value(), bob(), new MockHttpServletRequest(),
				new ExtendedModelMap()))
			.isEqualTo("redirect:/login?invite=revoked");
	}

	@Test
	void confirmingStashesTheTokenAndSendsThemOnSoTheGateClaimsIt() {
		// Redemption stays in the authorization manager, which is the one place every
		// request passes exactly once. The POST only arms it.
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();

		String view = this.controller.confirm(invitation.token().value(), bob(), request);

		assertThat(view).isEqualTo("redirect:/");
		assertThat(Invitations.pending(request)).isEqualTo(invitation.token());
	}

	@Test
	void confirmingSendsThemWhereverTheApplicationConfigured() {
		this.properties.setDefaultSuccessUrl("/dashboard");
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");

		assertThat(this.controller.confirm(invitation.token().value(), bob(), new MockHttpServletRequest()))
			.isEqualTo("redirect:/dashboard");
	}

	@Test
	void confirmingAnAlreadyDeadInvitationGoesToTheChooserAndStashesNothing() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(invitation.token(), new ApprovalKey("google", "someone"));
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(this.controller.confirm(invitation.token().value(), bob(), request))
			.isEqualTo("redirect:/login?invite=used");
		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void acceptingBeforeSigningInStashesTheTokenAndSendsThemToTheChooser() {
		Invitation invitation = this.store.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(this.controller.confirm(invitation.token().value(), null, request)).isEqualTo("redirect:/login");
		// The POST is the deliberate act, and it carries a CSRF token. This is the
		// ordinary flow: accept, then sign in, then the gate claims it.
		assertThat(Invitations.pending(request)).isEqualTo(invitation.token());
	}

	private static org.springframework.security.core.Authentication bob() {
		return org.springframework.security.authentication.UsernamePasswordAuthenticationToken.authenticated(
				"bob@example.com", "n/a",
				org.springframework.security.core.authority.AuthorityUtils.createAuthorityList("ROLE_USER"));
	}

}
