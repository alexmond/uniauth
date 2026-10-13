package org.alexmond.uniauth.invitation;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.InMemoryApprovalStore;
import org.alexmond.uniauth.approval.PrincipalIdentity;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Redemption, unit-tested away from the chain.
 *
 * <p>
 * The ordering is the whole point and it is easiest to see here: the event is published
 * <em>before</em> the approval is written, so a listener that throws leaves the principal
 * unadmitted rather than admitted-and-unlinked.
 */
class InvitationRedemptionTest {

	private static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	private static final ApprovalKey BOB = new ApprovalKey("google", "bob-sub");

	private static final PrincipalIdentity IDENTITY = new PrincipalIdentity("Jane Smith", "jane@example.com",
			Boolean.TRUE, "jane-sub");

	private InvitationStore invitations;

	private ApprovalStore approvals;

	private UniAuthProperties properties;

	private List<Object> published;

	@BeforeEach
	void freshCollaborators() {
		this.invitations = new InMemoryInvitationStore(Clock.systemUTC(), Duration.ofDays(14));
		this.approvals = new InMemoryApprovalStore();
		this.properties = new UniAuthProperties();
		this.properties.getApproval().getInvitations().setEnabled(true);
		this.published = new java.util.ArrayList<>();
	}

	@Test
	void anInvitedPrincipalIsApprovedWithTheInvitationAsApprover() {
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		boolean admitted = redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY,
				AuthProviderType.OAUTH2);

		assertThat(admitted).isTrue();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get().satisfies((record) -> {
			// The subjectRef, not the token: the token is a bearer credential and has no
			// business in an audit record, and "invitation:jane" is what an auditor wants
			// to read anyway.
			assertThat(record.decidedBy()).isEqualTo("invitation:jane");
			assertThat(record.roles()).containsExactly("FAMILY");
			assertThat(record.identity()).isEqualTo(IDENTITY);
			assertThat(record.mechanism()).isEqualTo(AuthProviderType.OAUTH2);
		});
	}

	@Test
	void theEventCarriesEverythingNeededToDoTheLinking() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(this.published).singleElement()
			.isEqualTo(new InvitationRedeemedEvent(JANE, "jane", IDENTITY, invitation.token()));
	}

	@Test
	void anInvitationWithNoRolesFallsBackToTheConfiguredDefaults() {
		// Without this an admitted principal arrives with OIDC_USER and SCOPE_* and no
		// ROLE_ at all, then gets refused by every hasRole() rule — exactly the bug #5
		// fixed.
		this.properties.getApproval().setDefaultRoles(new java.util.ArrayList<>(List.of("USER")));
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");

		redemption((event) -> this.published.add(event)).admit(requestHolding(invitation.token()), JANE, IDENTITY,
				AuthProviderType.OAUTH2);

		assertThat(this.approvals.find(JANE)).get()
			.extracting(org.alexmond.uniauth.approval.ApprovalRecord::roles)
			.isEqualTo(List.of("USER"));
	}

	@Test
	void theTokenIsClearedFromTheSessionOnceClaimed() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void aRequestHoldingNoTokenIsNotAdmittedAndNothingIsWritten() {
		boolean admitted = redemption((event) -> this.published.add(event)).admit(new MockHttpServletRequest(), JANE,
				IDENTITY, AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
		assertThat(this.published).isEmpty();
	}

	@Test
	void aSecondPrincipalCannotClaimTheSameInvitationAndTheTokenIsDropped() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		redemption((event) -> this.published.add(event)).admit(requestHolding(invitation.token()), JANE, IDENTITY,
				AuthProviderType.OAUTH2);
		MockHttpServletRequest bobsRequest = requestHolding(invitation.token());

		boolean admitted = redemption((event) -> this.published.add(event)).admit(bobsRequest, BOB,
				PrincipalIdentity.ofName("bob-sub"), AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(BOB)).isEqualTo(ApprovalStatus.UNKNOWN);
		// Dropped, so Bob is not re-attempting a dead token on every single request for
		// the life of his session.
		assertThat(Invitations.pending(bobsRequest)).isNull();
	}

	@Test
	void aListenerThatThrowsLeavesThePrincipalUnadmitted() {
		// Admitted-but-unlinked is worse than "try again": the person would be browsing
		// as nobody, holding a session no record backs.
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");

		boolean admitted = redemption((event) -> {
			throw new IllegalStateException("no such record");
		}).admit(requestHolding(invitation.token()), JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.PENDING);
	}

	@Test
	void afterAFailedListenerTheNextRequestRetriesAndSucceeds() {
		// The reason redeem is keyed by principal. If the claim made the token dead, one
		// transient failure would strand Jane with a URL that can never work again and no
		// way back except an administrator noticing.
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());
		redemption((event) -> {
			throw new IllegalStateException("the database was down");
		}).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);
		assertThat(Invitations.pending(request)).isNotNull();

		boolean admitted = redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY,
				AuthProviderType.OAUTH2);

		assertThat(admitted).isTrue();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get()
			.extracting(org.alexmond.uniauth.approval.ApprovalRecord::roles)
			.isEqualTo(List.of("FAMILY"));
	}

	@Test
	void anInvitationDoesNotUndoARefusalAPersonMade() {
		// The retry window again. A claim whose listener threw leaves the principal
		// PENDING with the token still on their session, and a PENDING record is exactly
		// what an approver looks at and refuses. Writing APPROVED on the retry would
		// silently revert their decision — and they would have no reason to suspect an
		// invitation was holding the door open.
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());
		redemption((event) -> {
			throw new IllegalStateException("the application's database was down");
		}).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.approvals.decide(JANE, ApprovalStatus.DENIED, "admin", List.of());

		boolean admitted = redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY,
				AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.DENIED);
		assertThat(this.published).isEmpty();
	}

	@Test
	void anApproversDecisionAndTheRolesTheyGrantedSurviveTheLinkBeingMadeLater() {
		// Replay. A claim whose listener threw leaves the principal PENDING with the
		// token retained for the retry, and a PENDING record is exactly what an approver
		// acts on. If the retry then wrote the invitation's own decision, it would
		// replace theirs — including the roles they deliberately chose to grant, which
		// may be narrower than whatever the invitation carries.
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY", "ADMIN"), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());
		redemption((event) -> {
			throw new IllegalStateException("the application's database was down");
		}).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.approvals.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("USER"));

		redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(this.approvals.find(JANE)).get().satisfies((record) -> {
			assertThat(record.decidedBy()).isEqualTo("admin");
			assertThat(record.roles()).containsExactly("USER");
		});
		// The link is still made, because that is what was actually outstanding.
		assertThat(this.published).hasSize(1);
		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void aRefusalThatLandsWhileTheListenerIsRunningStillStands() {
		// Checking the refusal and writing the approval are two separate calls, and
		// between them sits the application's own listener — a callback that can take as
		// long as it likes. That is more than long enough for an approver to refuse, and
		// a listener that refuses during its own call is the deterministic version of
		// exactly that race.
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");

		boolean admitted = redemption((event) -> this.approvals.decide(JANE, ApprovalStatus.DENIED, "admin", List.of()))
			.admit(requestHolding(invitation.token()), JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(admitted).isFalse();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.DENIED);
	}

	@Test
	void anInvitationStillAdmitsSomebodyInviteOnlyTurnedAwayByItself() {
		// The fix above has to stay narrow, and this is why. Under invite-only every
		// first-time visitor is recorded DENIED, so anybody who signed in before opening
		// their link would be locked out permanently if an invitation could not override
		// it. Only a refusal a person made is final.
		this.approvals.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.approvals.decide(JANE, ApprovalStatus.DENIED, InvitationRedemption.INVITE_ONLY, List.of());
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");

		boolean admitted = redemption((event) -> this.published.add(event)).admit(requestHolding(invitation.token()),
				JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(admitted).isTrue();
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
	}

	@Test
	void aRevokedInvitationIsNotRedeemedAndTheTokenIsDropped() {
		Invitation invitation = this.invitations.create("jane", null, List.of(), "admin");
		this.invitations.revoke(invitation.token(), "admin");
		MockHttpServletRequest request = requestHolding(invitation.token());

		assertThat(redemption((event) -> this.published.add(event)).admit(request, JANE, IDENTITY,
				AuthProviderType.OAUTH2))
			.isFalse();
		assertThat(Invitations.pending(request)).isNull();
	}

	@Test
	void manySimultaneousRequestsFromTheSamePrincipalAdmitThemOnceAndWriteOneApproval() throws Exception {
		// Review Focus 4, the double-click, through the whole collaborator rather than
		// only the store.
		Invitation invitation = this.invitations.create("jane", null, List.of("FAMILY"), "admin");
		int attempts = 8;
		CountDownLatch startLine = new CountDownLatch(1);
		AtomicInteger admitted = new AtomicInteger();
		List<Object> events = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
		InvitationRedemption redemption = redemption(events::add);
		ExecutorService pool = Executors.newFixedThreadPool(attempts);
		try {
			for (int i = 0; i < attempts; i++) {
				MockHttpServletRequest request = requestHolding(invitation.token());
				pool.submit(() -> {
					try {
						startLine.await();
						if (redemption.admit(request, JANE, IDENTITY, AuthProviderType.OAUTH2)) {
							admitted.incrementAndGet();
						}
					}
					catch (InterruptedException interrupted) {
						Thread.currentThread().interrupt();
					}
				});
			}
			startLine.countDown();
			pool.shutdown();
			assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
		}
		finally {
			pool.shutdownNow();
		}

		// Every one is the same person, so every one succeeds; the record settles once.
		assertThat(admitted.get()).isEqualTo(attempts);
		assertThat(this.approvals.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.approvals.find(JANE)).get()
			.extracting(org.alexmond.uniauth.approval.ApprovalRecord::roles)
			.isEqualTo(List.of("FAMILY"));
	}

	private MockHttpServletRequest requestHolding(InvitationToken token) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		Invitations.stash(request, token);
		return request;
	}

	private InvitationRedemption redemption(java.util.function.Consumer<Object> publisher) {
		return new InvitationRedemption(this.invitations, this.approvals, publisher::accept, this.properties);
	}

}
