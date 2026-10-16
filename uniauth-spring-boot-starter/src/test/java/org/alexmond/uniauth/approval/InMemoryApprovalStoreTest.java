package org.alexmond.uniauth.approval;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.alexmond.uniauth.provider.AuthProviderType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The store contract, exercised on the in-memory default.
 *
 * <p>
 * {@code decide} on a key the store has never seen is the ambiguity #35 raised: the
 * interface did not say whether a record may be created, so an implementor could not tell
 * which behaviour was required, and the in-memory default did nothing at all — silently.
 * Both halves are pinned here, because the answer only means something if the two agree.
 */
class InMemoryApprovalStoreTest {

	private static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");

	private static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	private static final PrincipalIdentity IDENTITY = new PrincipalIdentity("Jane Smith", "jane@example.com", true,
			"jane-sub");

	private InMemoryApprovalStore store;

	@BeforeEach
	void freshStore() {
		this.store = new InMemoryApprovalStore(Clock.fixed(NOW, ZoneOffset.UTC));
	}

	@Test
	void anUnseenPrincipalIsUnknownRatherThanPending() {
		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
		assertThat(this.store.find(JANE)).isEmpty();
	}

	@Test
	void decidingOnAKeyTheStoreHasNeverSeenCreatesNothing() {
		// The contract, not an accident of the implementation: decide settles a record
		// that exists. Creating one here would invent a decision about a principal
		// nobody has ever seen, with no identity and no mechanism to show an approver
		// reading the queue afterwards.
		this.store.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("ADMIN"));

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
		assertThat(this.store.find(JANE)).isEmpty();
	}

	@Test
	void recordPendingThenDecideIsHowSomebodyIsApprovedBeforeTheyArrive() {
		// Which makes pre-approval possible rather than impossible: an administrator —
		// or the configuration that admits the first one — records the sighting itself
		// and then decides it. This is the documented route, and the reason decide not
		// creating records is a contract worth stating rather than a limitation.
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.APPROVED, "bootstrap", List.of("ADMIN"));

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.store.find(JANE)).get().satisfies((record) -> {
			assertThat(record.roles()).containsExactly("ADMIN");
			assertThat(record.decidedBy()).isEqualTo("bootstrap");
			assertThat(record.decidedAt()).isEqualTo(NOW);
		});
	}

	@Test
	void aDecisionMustBeApprovedOrDenied() {
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.store.decide(JANE, ApprovalStatus.PENDING, "admin", List.of()));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.store.decide(JANE, ApprovalStatus.UNKNOWN, "admin", List.of()));
	}

	@Test
	void recordingTheSameSightingTwiceDoesNotReopenADecision() {
		// A second request from an approved principal must not put them back in the
		// queue, and an approver's roles must survive it.
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("FAMILY"));

		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.store.find(JANE)).get()
			.satisfies((record) -> assertThat(record.roles()).containsExactly("FAMILY"));
	}

	@Test
	void pendingHoldsOnlyThoseStillWaiting() {
		ApprovalKey bob = new ApprovalKey("saml", "bob-nameid");
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.recordPending(bob, IDENTITY, AuthProviderType.SAML);
		this.store.decide(bob, ApprovalStatus.DENIED, "admin", List.of());

		assertThat(this.store.pending()).extracting(ApprovalRecord::key).containsExactly(JANE);
	}

	@Test
	void removingForgetsAPrincipalEntirelySoTheyCanBeReconsidered() {
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.DENIED, "admin", List.of());

		this.store.remove(JANE);

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
	}

	@Test
	void removingSomebodyTheStoreNeverHeldIsNotAnError() {
		this.store.remove(JANE);

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
	}

}
