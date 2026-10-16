package org.alexmond.uniauth.test;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.PrincipalIdentity;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The rules an {@link ApprovalStore} has to honour, whatever it is backed by.
 *
 * <p>
 * {@code InMemoryApprovalStore} is not production-fit — it empties on restart and is
 * invisible to a second instance — so a real deployment supplies its own, and then
 * nothing but prose told it what the library expects. Two of these rules were not even
 * prose until recently: what {@code decide} does with a key it has never seen, and that a
 * repeated sighting must not reopen a settled decision.
 *
 * <p>
 * Extend this and supply the store:
 *
 * <pre>
 * class JdbcApprovalStoreTest extends ApprovalStoreContract {
 *
 *     &#64;Override
 *     protected ApprovalStore createStore(Clock clock) {
 *         return new JdbcApprovalStore(dataSource, clock);
 *     }
 *
 * }
 * </pre>
 *
 * @see InvitationStoreContract
 */
public abstract class ApprovalStoreContract {

	/** The moment every test starts from, so recorded instants are assertable. */
	protected static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");

	/** A federated principal. */
	protected static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	/** The same name at another provider, which must be a different person. */
	protected static final ApprovalKey JANE_ELSEWHERE = new ApprovalKey("internal", "jane-sub");

	/** What a mechanism managed to learn about the principal. */
	protected static final PrincipalIdentity IDENTITY = new PrincipalIdentity("Jane Smith", "jane@example.com", true,
			"jane-sub");

	private MutableClock clock;

	private ApprovalStore store;

	/**
	 * Builds a store reading the given clock, holding no records.
	 *
	 * <p>
	 * Called before every test. An implementation backed by a database should truncate
	 * its table here, or use a fresh schema.
	 * @param clock the clock the store must read for the instants it records; never
	 * {@code null}
	 * @return the store under test
	 */
	protected abstract ApprovalStore createStore(Clock clock);

	/**
	 * The store under test, at {@link #NOW}.
	 * @return the store built for this test
	 */
	protected final ApprovalStore store() {
		return this.store;
	}

	/**
	 * Moves the clock the store was built with.
	 * @param later the new now
	 */
	protected final void timeTravelTo(Instant later) {
		this.clock.set(later);
	}

	@BeforeEach
	void freshStore() {
		this.clock = new MutableClock(NOW);
		this.store = createStore(this.clock);
	}

	@Test
	void anUnseenPrincipalIsUnknownRatherThanPending() {
		// UNKNOWN and PENDING are different answers: the gate records a first sighting
		// when it sees UNKNOWN, and treating an absent record as already waiting would
		// mean nobody is ever recorded and the queue stays empty.
		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
		assertThat(this.store.find(JANE)).isEmpty();
	}

	@Test
	void recordPendingPutsTheSightingWhereAnApproverWillFindIt() {
		ApprovalRecord recorded = this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(recorded.key()).isEqualTo(JANE);
		assertThat(recorded.status()).isEqualTo(ApprovalStatus.PENDING);
		assertThat(recorded.identity()).isEqualTo(IDENTITY);
		assertThat(recorded.mechanism()).isEqualTo(AuthProviderType.OAUTH2);
		assertThat(recorded.firstSeen()).isEqualTo(NOW);
		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.PENDING);
		assertThat(this.store.pending()).extracting(ApprovalRecord::key).contains(JANE);
	}

	@Test
	void keysAreScopedToTheProviderThatAnsweredAndNotToTheNameAlone() {
		// Approving "jane" from the internal store must not admit "jane" from Google.
		// A store keying on the principal alone collapses two people into one, which is
		// an authorization failure rather than a storage detail.
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("USER"));

		assertThat(this.store.statusOf(JANE_ELSEWHERE)).isEqualTo(ApprovalStatus.UNKNOWN);
	}

	@Test
	void decidingOnAKeyTheStoreHasNeverSeenCreatesNothing() {
		// Contract, not an implementation detail. Creating a record here would invent a
		// decision about somebody with no identity and no mechanism behind it — a row
		// whoever reads the queue afterwards cannot make sense of.
		this.store.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("ADMIN"));

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
		assertThat(this.store.find(JANE)).isEmpty();
	}

	@Test
	void recordPendingThenDecideIsHowSomebodyIsApprovedBeforeTheyArrive() {
		// Which is what makes pre-approval possible rather than impossible, and is the
		// documented route for the first administrator under invite-only.
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
	void anApproverSRolesAreKeptBecauseAFederatedPrincipalHasNoneOfItsOwn() {
		// An approval granting nothing admits somebody who is then refused by every
		// hasRole rule in the application — a working sign-in that reaches nothing,
		// which reads as a broken application rather than a permissions decision.
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.SAML);
		this.store.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("FAMILY", "CURATOR"));

		assertThat(this.store.find(JANE)).get()
			.satisfies((record) -> assertThat(record.roles()).containsExactlyInAnyOrder("FAMILY", "CURATOR"));
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
	void arrivingAgainDoesNotReopenASettledDecision() {
		// Every authenticated request passes the gate, and the gate records a sighting.
		// A store that overwrites on each one puts an approved principal back in the
		// queue on their second page view, losing the approver's roles with it.
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("FAMILY"));

		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.store.find(JANE)).get()
			.satisfies((record) -> assertThat(record.roles()).containsExactly("FAMILY"));
	}

	@Test
	void arrivingAgainDoesNotReopenARefusal() {
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.DENIED, "admin", List.of());

		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.DENIED);
	}

	@Test
	void pendingHoldsOnlyThoseStillWaiting() {
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.recordPending(JANE_ELSEWHERE, IDENTITY, AuthProviderType.INTERNAL);
		this.store.decide(JANE_ELSEWHERE, ApprovalStatus.DENIED, "admin", List.of());

		assertThat(this.store.pending()).extracting(ApprovalRecord::key).containsExactly(JANE);
	}

	@Test
	void removingForgetsAPrincipalEntirelySoTheyCanBeReconsidered() {
		// The only route back for somebody denied. A store that keeps the row and
		// reports DENIED for ever gives an administrator no way to change their mind.
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.DENIED, "admin", List.of());

		this.store.remove(JANE);

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
		assertThat(this.store.find(JANE)).isEmpty();
	}

	@Test
	void removingSomebodyTheStoreNeverHeldIsNotAnError() {
		this.store.remove(JANE);

		assertThat(this.store.statusOf(JANE)).isEqualTo(ApprovalStatus.UNKNOWN);
	}

	@Test
	void simultaneousFirstSightingsDoNotLoseADecision() throws Exception {
		// A federated login lands several requests at once — a page and its assets —
		// and every one of them passes the gate. A read-then-write recordPending lets a
		// late one overwrite a decision made between its read and its write, which puts
		// an approved principal back in the queue for no reason anybody can reconstruct.
		this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2);
		this.store.decide(JANE, ApprovalStatus.APPROVED, "admin", List.of("FAMILY"));
		int racers = 16;

		race(racers, () -> this.store.recordPending(JANE, IDENTITY, AuthProviderType.OAUTH2));

		assertThat(this.store.statusOf(JANE)).as("a concurrent sighting must not undo a decision")
			.isEqualTo(ApprovalStatus.APPROVED);
		assertThat(this.store.find(JANE)).get()
			.satisfies((record) -> assertThat(record.roles()).containsExactly("FAMILY"));
	}

	/**
	 * Runs {@code work} on {@code count} threads released together.
	 * @param count how many threads
	 * @param work what each one does
	 * @throws InterruptedException if waiting for the threads is interrupted
	 */
	private static void race(int count, Runnable work) throws InterruptedException {
		CountDownLatch ready = new CountDownLatch(count);
		CountDownLatch go = new CountDownLatch(1);
		CountDownLatch done = new CountDownLatch(count);
		try (ExecutorService pool = Executors.newFixedThreadPool(count)) {
			for (int i = 0; i < count; i++) {
				pool.execute(() -> {
					ready.countDown();
					try {
						go.await();
						work.run();
					}
					catch (InterruptedException interrupted) {
						Thread.currentThread().interrupt();
					}
					finally {
						done.countDown();
					}
				});
			}
			try {
				assertThat(ready.await(10, TimeUnit.SECONDS)).as("every thread reached the start line").isTrue();
			}
			finally {
				// Released even when the assertion above fails, or the pool's own close
				// would wait for ever on threads still parked on the start line.
				go.countDown();
			}
			assertThat(done.await(10, TimeUnit.SECONDS)).as("every thread finished").isTrue();
		}
	}

}
