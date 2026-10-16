package org.alexmond.uniauth.test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationStatus;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.InvitationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * The rules an {@link InvitationStore} has to honour, whatever it is backed by.
 *
 * <p>
 * A durable store is the application's job by design — UniAuth owns the flow and never
 * the table. The cost of that bargain is that its correctness rules lived only in prose,
 * so every implementor rediscovered them alone, and the most important one cannot be
 * found by testing carefully: {@code redeem} must be a single compare-and-set, and a
 * read-then-write passes every single-threaded test while admitting two people under
 * load.
 *
 * <p>
 * Extend this and supply the store:
 *
 * <pre>
 * class JdbcInvitationStoreTest extends InvitationStoreContract {
 *
 *     &#64;Override
 *     protected InvitationStore createStore(Clock clock) {
 *         return new JdbcInvitationStore(dataSource, clock, Duration.ofDays(14));
 *     }
 *
 * }
 * </pre>
 *
 * <p>
 * The {@link Clock} is not a convenience. Expiry is the one rule that cannot be tested
 * without controlling time, and a store that reads {@code Instant.now()} internally
 * cannot be proved to honour it — which is why the clock is a constructor argument here
 * and in {@code InMemoryInvitationStore}.
 *
 * @see ApprovalStoreContract
 */
public abstract class InvitationStoreContract {

	/**
	 * The moment every test starts from. Fixed so that "expired" and "still open" are
	 * decidable rather than a race with the wall clock.
	 */
	protected static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");

	/** Somebody who claims an invitation. */
	protected static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	/** Somebody else, who must not get the same one. */
	protected static final ApprovalKey BOB = new ApprovalKey("google", "bob-sub");

	private MutableClock clock;

	private InvitationStore store;

	/**
	 * Builds a store reading the given clock, empty of invitations.
	 *
	 * <p>
	 * Called before every test, so each one starts clean. An implementation backed by a
	 * database should truncate its table here, or use a fresh schema.
	 * @param clock the clock the store must read for expiry and for the instants it
	 * records; never {@code null}
	 * @return the store under test
	 */
	protected abstract InvitationStore createStore(Clock clock);

	/**
	 * The store under test, at {@link #NOW}.
	 * @return the store built for this test
	 */
	protected final InvitationStore store() {
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
	void aCreatedInvitationIsOpenAndFindableByItsToken() {
		Invitation created = this.store.create("jane-record", null, List.of("FAMILY"), "admin");

		assertThat(created.subjectRef()).isEqualTo("jane-record");
		assertThat(created.roles()).containsExactly("FAMILY");
		assertThat(created.status(NOW)).isEqualTo(InvitationStatus.OPEN);
		assertThat(this.store.find(created.token())).get().isEqualTo(created);
	}

	@Test
	void anUnknownTokenIsAMissRatherThanAnError() {
		assertThat(this.store.find(InvitationToken.generate())).isEmpty();
	}

	@Test
	void redeemingClaimsTheInvitationForThatPrincipal() {
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");

		Invitation claimed = this.store.redeem(created.token(), JANE);

		assertThat(claimed.usedBy()).isEqualTo(JANE);
		assertThat(claimed.usedAt()).isNotNull();
		assertThat(claimed.status(NOW)).isEqualTo(InvitationStatus.USED);
		assertThat(this.store.find(created.token())).get()
			.satisfies((persisted) -> assertThat(persisted.usedBy()).isEqualTo(JANE));
	}

	@Test
	void oneUseMeansOnePersonAndNotOneRequest() {
		// The rule that makes a failed listener survivable. InvitationRedeemedEvent is
		// published before the approval is written, so a listener that throws leaves the
		// principal pending with the claim intact — and the next request has to get them
		// in. A store that kills the token on first claim strands the invited person
		// after one transient error.
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		Invitation again = this.store.redeem(created.token(), JANE);

		assertThat(again.usedBy()).isEqualTo(JANE);
		assertThat(again.subjectRef()).isEqualTo("jane-record");
	}

	@Test
	void aDifferentPrincipalCannotClaimAnInvitationAlreadyTaken() {
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), BOB));
		assertThat(this.store.find(created.token())).get()
			.satisfies((persisted) -> assertThat(persisted.usedBy()).isEqualTo(JANE));
	}

	@Test
	void anExpiredInvitationCannotBeRedeemed() {
		Invitation created = this.store.create("jane-record", Duration.ofSeconds(1), List.of(), "admin");

		timeTravelTo(NOW.plusSeconds(60));

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), JANE));
	}

	@Test
	void expiryIsInclusiveSoAnInvitationIsDeadAtItsOwnExpiryInstant() {
		// Matching JWT exp, HTTP Expires and cookie max-age rather than inventing a
		// convention. An implementation that treats the boundary as still open gives
		// every invitation one extra tick of life, which nothing will ever notice and
		// which makes two stores disagree.
		Invitation created = this.store.create("jane-record", Duration.ofSeconds(60), List.of(), "admin");

		assertThat(created.status(created.expiresAt().minusNanos(1))).isEqualTo(InvitationStatus.OPEN);
		assertThat(created.status(created.expiresAt())).isEqualTo(InvitationStatus.EXPIRED);
	}

	@Test
	void expiringDuringTheRetryWindowDoesNotStrandThePrincipalWhoAlreadyClaimedIt() {
		// The retry window can be as long as an outage, so it can outlive the invitation.
		// Somebody who already holds the claim must still get in — the invitation is not
		// being claimed again, it is being honoured.
		Invitation created = this.store.create("jane-record", Duration.ofSeconds(60), List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		timeTravelTo(NOW.plusSeconds(600));

		assertThat(this.store.redeem(created.token(), JANE).usedBy()).isEqualTo(JANE);
	}

	@Test
	void aRevokedInvitationCannotBeRedeemed() {
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		this.store.revoke(created.token(), "admin");

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), JANE));
		assertThat(this.store.find(created.token())).get()
			.satisfies((persisted) -> assertThat(persisted.status(NOW)).isEqualTo(InvitationStatus.REVOKED));
	}

	@Test
	void revokingOutranksTheRetryAndRefusesEvenThePrincipalWhoAlreadyClaimedIt() {
		// The one that makes revocation mean anything. The retry window is exactly when
		// somebody intervenes, so a revocation inside it must not be undone by the next
		// retry — otherwise revoking an invitation somebody is mid-claim does nothing.
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		this.store.revoke(created.token(), "admin");

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), JANE));
	}

	@Test
	void revokingAClaimedInvitationDoesNotUnclaimIt() {
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		this.store.revoke(created.token(), "admin");

		assertThat(this.store.find(created.token())).get()
			.satisfies((persisted) -> assertThat(persisted.usedBy()).isEqualTo(JANE));
	}

	@Test
	void revokingAnUnknownTokenIsNotAnError() {
		org.assertj.core.api.Assertions.assertThatNoException()
			.isThrownBy(() -> this.store.revoke(InvitationToken.generate(), "admin"));
	}

	@Test
	void listWithNoArgumentsReturnsEverything() {
		this.store.create("jane-record", null, List.of(), "admin");
		this.store.create("bob-record", null, List.of(), "admin");

		assertThat(this.store.list()).hasSize(2);
	}

	@Test
	void listFiltersByStatus() {
		// An administrator cannot manage invitations they cannot list, which is why this
		// SPI can enumerate from the start where ApprovalStore cannot.
		Invitation open = this.store.create("jane-record", null, List.of(), "admin");
		Invitation used = this.store.create("bob-record", null, List.of(), "admin");
		this.store.redeem(used.token(), BOB);

		assertThat(this.store.list(InvitationStatus.OPEN)).extracting(Invitation::token).containsExactly(open.token());
		assertThat(this.store.list(InvitationStatus.USED)).extracting(Invitation::token).containsExactly(used.token());
	}

	@Test
	void findByUsedByAnswersWhichRecordAPrincipalHolds() {
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		assertThat(this.store.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-record"));
		assertThat(this.store.findByUsedBy(BOB)).isEmpty();
	}

	@Test
	void findByUsedByStillFindsAClaimThatWasLaterRevoked() {
		// Revocation outranks use in status(), so an implementation overriding this with
		// a query filtered on USED would answer "holds nothing" for precisely the person
		// whose link needs repairing.
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);
		this.store.revoke(created.token(), "admin");

		assertThat(this.store.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-record"));
	}

	@Test
	void aNonPositiveTtlIsRejectedRatherThanCreatingSomethingBornExpired() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.store.create("jane-record", Duration.ZERO, List.of(), "admin"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.store.create("jane-record", Duration.ofSeconds(-1), List.of(), "admin"));
	}

	@Test
	void aMissingSubjectRefIsRejectedBecauseAnInvitationToNobodyAdmitsAnybody() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.store.create(null, null, List.of(), "admin"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.store.create("  ", null, List.of(), "admin"));
	}

	@Test
	void onlyOneOfManySimultaneousPrincipalsClaimsTheInvitation() throws Exception {
		// The case a read-then-write implementation passes every other test here and
		// fails: each thread reads an unclaimed invitation, each decides it may have it,
		// and two people are bound to one record. redeem has to be a compare-and-set.
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		int racers = 16;
		AtomicInteger admitted = new AtomicInteger();

		race(racers, (index) -> {
			try {
				this.store.redeem(created.token(), new ApprovalKey("google", "racer-" + index));
				admitted.incrementAndGet();
			}
			catch (InvitationStore.InvitationNotRedeemableException expected) {
				// Everybody but the winner.
			}
		});

		assertThat(admitted.get()).as("exactly one principal may claim an invitation").isEqualTo(1);
		assertThat(this.store.find(created.token())).get()
			.satisfies((persisted) -> assertThat(persisted.usedBy()).isNotNull());
	}

	@Test
	void manySimultaneousRequestsFromTheSamePrincipalAllSucceed() throws Exception {
		// The other half of the same rule, and the reason it is keyed by principal. Two
		// requests on one session can both reach redemption before either clears the
		// token, so a store that refuses the second refuses somebody who is approved.
		Invitation created = this.store.create("jane-record", null, List.of(), "admin");
		int attempts = 16;
		AtomicInteger succeeded = new AtomicInteger();

		race(attempts, (index) -> {
			this.store.redeem(created.token(), JANE);
			succeeded.incrementAndGet();
		});

		assertThat(succeeded.get()).as("the same principal may claim the same invitation repeatedly")
			.isEqualTo(attempts);
	}

	/**
	 * Runs {@code work} on {@code count} threads released together.
	 *
	 * <p>
	 * A latch rather than staggered starts, because the defect being hunted is a window
	 * between a read and a write. Threads that begin a millisecond apart will not find
	 * it.
	 * @param count how many threads
	 * @param work what each one does, given its own index
	 * @throws InterruptedException if waiting for the threads is interrupted
	 */
	private static void race(int count, java.util.function.IntConsumer work) throws InterruptedException {
		CountDownLatch ready = new CountDownLatch(count);
		CountDownLatch go = new CountDownLatch(1);
		CountDownLatch done = new CountDownLatch(count);
		try (ExecutorService pool = Executors.newFixedThreadPool(count)) {
			for (int i = 0; i < count; i++) {
				int index = i;
				pool.execute(() -> {
					ready.countDown();
					try {
						go.await();
						work.accept(index);
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
