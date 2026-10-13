package org.alexmond.uniauth.approval;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InMemoryInvitationStore;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.Invitations;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The gate, with invitations in play.
 *
 * <p>
 * Driven directly rather than through the chain, because the cases that matter are
 * combinations of standing, stashed token and {@code invite-only} — there are more of
 * them than it is worth booting a context for, and the chain-level proof lives in
 * {@code UniAuthInvitationTest}.
 */
class ApprovalAuthorizationManagerTest {

	private static final ApprovalKey ALICE = new ApprovalKey("internal", "alice");

	private ApprovalStore approvals;

	private InvitationStore invitations;

	private UniAuthProperties properties;

	@BeforeEach
	void freshCollaborators() {
		this.approvals = new InMemoryApprovalStore();
		this.invitations = new InMemoryInvitationStore(Clock.systemUTC(), Duration.ofDays(14));
		this.properties = new UniAuthProperties();
		this.properties.getApproval().setRequireFor(new java.util.ArrayList<>(List.of(AuthProviderType.INTERNAL)));
		this.properties.getApproval().getInvitations().setEnabled(true);
	}

	@Test
	void anInvitedPrincipalIsLetThroughOnTheFirstRequestWithNoPendingStep() {
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();
		Invitations.stash(request, invitation.token());

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isTrue();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(request.getAttribute(ApprovalAuthorizationManager.PENDING_ATTRIBUTE)).isNull();
	}

	@Test
	void anUninvitedPrincipalIsStillHeldPendingAsBefore() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isFalse();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.PENDING);
		assertThat(request.getAttribute(ApprovalAuthorizationManager.PENDING_ATTRIBUTE)).isEqualTo(Boolean.TRUE);
	}

	@Test
	void anAlreadyPendingPrincipalCanStillClaimAnInvitation() {
		// The restart case. The session was lost mid-login, so they landed as PENDING;
		// reopening the URL has to work, and conditioning redemption on UNKNOWN would
		// mean it never does.
		this.approvals.recordPending(ALICE, PrincipalIdentity.ofName("alice"), AuthProviderType.INTERNAL);
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = new MockHttpServletRequest();
		Invitations.stash(request, invitation.token());

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isTrue();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void inviteOnlyRefusesAnUninvitedPrincipalOutrightRatherThanHoldingThem() {
		this.properties.getApproval().getInvitations().setInviteOnly(true);
		MockHttpServletRequest request = new MockHttpServletRequest();

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(request));

		assertThat(decision.isGranted()).isFalse();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.DENIED);
		// Not flagged, so the access-denied handler leaves it a plain 403. Telling
		// somebody who will never be admitted to keep waiting is a lie.
		assertThat(request.getAttribute(ApprovalAuthorizationManager.PENDING_ATTRIBUTE)).isNull();
	}

	@Test
	void inviteOnlyRecordsWhyTheRefusalHappened() {
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(this.approvals.find(ALICE)).get().extracting(ApprovalRecord::decidedBy).isEqualTo("invite-only");
	}

	@Test
	void inviteOnlyDoesNotRevokeSomebodyAlreadyWaiting() {
		// They were recorded under an earlier configuration. Flipping a waiting person to
		// DENIED turns a queue a human was about to read into a silent refusal.
		this.approvals.recordPending(ALICE, PrincipalIdentity.ofName("alice"), AuthProviderType.INTERNAL);
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.PENDING);
	}

	@Test
	void inviteOnlyDoesNotTouchAnAlreadyApprovedPrincipal() {
		this.approvals.recordPending(ALICE, PrincipalIdentity.ofName("alice"), AuthProviderType.INTERNAL);
		this.approvals.decide(ALICE, ApprovalStatus.APPROVED, "admin", List.of("USER"));
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void anUngatedMechanismIsNotSubjectToInviteOnlyEither() {
		this.properties.getApproval().setRequireFor(new java.util.ArrayList<>(List.of(AuthProviderType.OAUTH2)));
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		AuthorizationDecision decision = manager().authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isTrue();
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.UNKNOWN);
	}

	@Test
	void anonymousRequestsAreStillRefusedSoTheEntryPointRedirects() {
		AuthorizationDecision decision = manager().authorize(
				() -> new AnonymousAuthenticationToken("key", "anonymousUser",
						AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")),
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void withNoRedemptionCollaboratorTheGateBehavesExactlyAsItDidBefore() {
		// Invitations switched off: the three-argument constructor is what
		// ApprovalConfiguration used before this feature, and it must still hold.
		ApprovalAuthorizationManager plain = new ApprovalAuthorizationManager(this.approvals, new MechanismResolver(),
				this.properties);
		this.properties.getApproval().getInvitations().setInviteOnly(true);

		AuthorizationDecision decision = plain.authorize(ApprovalAuthorizationManagerTest::alice,
				new RequestAuthorizationContext(new MockHttpServletRequest()));

		assertThat(decision.isGranted()).isFalse();
		// PENDING, not DENIED: invite-only cannot mean anything without invitations.
		assertThat(this.approvals.statusOf(ALICE)).isEqualTo(ApprovalStatus.PENDING);
	}

	private ApprovalAuthorizationManager manager() {
		InvitationRedemption redemption = new InvitationRedemption(this.invitations, this.approvals, (event) -> {
		}, this.properties);
		return new ApprovalAuthorizationManager(this.approvals, new MechanismResolver(), this.properties, redemption);
	}

	private static Authentication alice() {
		return UsernamePasswordAuthenticationToken.authenticated("alice", "n/a",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
	}

}
