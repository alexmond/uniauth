package org.alexmond.uniauth.invitation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The store contract, exercised on the in-memory default.
 *
 * <p>
 * {@code redeem} is the only place one-use is enforced, and the only thing an implementor
 * can get wrong silently — a read-then-write passes every single-threaded test and admits
 * two people under load. Hence the concurrency cases.
 */
class InMemoryInvitationStoreTest {

	private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

	private static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	private static final ApprovalKey BOB = new ApprovalKey("google", "bob-sub");

	private InMemoryInvitationStore store;

	@BeforeEach
	void freshStore() {
		this.store = new InMemoryInvitationStore(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofDays(14));
	}

	@Test
	void aCreatedInvitationIsOpenAndFindable() {
		Invitation created = this.store.create("jane", Duration.ofDays(7), List.of("USER"), "admin");

		assertThat(created.status(NOW)).isEqualTo(InvitationStatus.OPEN);
		assertThat(created.subjectRef()).isEqualTo("jane");
		assertThat(created.createdBy()).isEqualTo("admin");
		assertThat(created.expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(7)));
		assertThat(this.store.find(created.token())).contains(created);
	}

	@Test
	void aNullTtlFallsBackToTheConfiguredDefault() {
		// Review Focus 3. An SPI implementor will pass null, and "never expires" is the
		// wrong default for a credential anyone can forward.
		Invitation created = this.store.create("jane", null, List.of(), "admin");

		assertThat(created.expiresAt()).isEqualTo(NOW.plus(Duration.ofDays(14)));
	}

	@Test
	void aNonPositiveTtlIsRejectedRatherThanCreatingSomethingBornExpired() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.store.create("jane", Duration.ZERO, List.of(), "a"));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.store.create("jane", Duration.ofSeconds(-1), List.of(), "a"));
	}

	@Test
	void blankAndNullRolesAreDroppedSoNobodyIsGrantedRoleNull() {
		// Review Focus 3. These reach ApprovalAuthoritiesFilter, which prefixes whatever
		// it is handed — "ROLE_null" would be granted and then never match anything.
		List<String> dirty = new ArrayList<>();
		dirty.add("USER");
		dirty.add(null);
		dirty.add("   ");
		dirty.add(" ADMIN ");

		Invitation created = this.store.create("jane", null, dirty, "admin");

		assertThat(created.roles()).containsExactly("USER", "ADMIN");
	}

	@Test
	void aMissingSubjectRefIsRejected() {
		// The subjectRef is the whole point: an invitation to nobody in particular is a
		// bearer token for an unidentified record.
		assertThatIllegalArgumentException().isThrownBy(() -> this.store.create("  ", null, List.of(), "admin"));
	}

	@Test
	void anUnknownTokenIsAMissRatherThanAnError() {
		assertThat(this.store.find(InvitationToken.generate())).isEmpty();
	}

	@Test
	void redeemingClaimsTheInvitationForThatPrincipal() {
		Invitation created = this.store.create("jane", null, List.of("USER"), "admin");

		Invitation claimed = this.store.redeem(created.token(), JANE);

		assertThat(claimed.usedBy()).isEqualTo(JANE);
		assertThat(claimed.usedAt()).isEqualTo(NOW);
		assertThat(claimed.status(NOW)).isEqualTo(InvitationStatus.USED);
		assertThat(this.store.find(created.token())).contains(claimed);
	}

	@Test
	void reclaimingWithTheSameKeyIsANoOpSoAFailedListenerCanBeRetried() {
		// The property that stops a transient application failure stranding Jane with a
		// URL that can never work again. One-use means one principal, not one request.
		Invitation created = this.store.create("jane", null, List.of("USER"), "admin");
		Invitation first = this.store.redeem(created.token(), JANE);

		Invitation again = this.store.redeem(created.token(), JANE);

		assertThat(again).isEqualTo(first);
		assertThat(again.usedAt()).isEqualTo(first.usedAt());
	}

	@Test
	void aDifferentPrincipalCannotClaimAnInvitationAlreadyTaken() {
		Invitation created = this.store.create("jane", null, List.of("USER"), "admin");
		this.store.redeem(created.token(), JANE);

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), BOB));
	}

	@Test
	void anExpiredInvitationCannotBeRedeemed() {
		InMemoryInvitationStore shortLived = new InMemoryInvitationStore(Clock.fixed(NOW, ZoneOffset.UTC),
				Duration.ofDays(14));
		Invitation created = shortLived.create("jane", Duration.ofSeconds(1), List.of(), "admin");
		InMemoryInvitationStore later = adopt(shortLived, NOW.plusSeconds(60));

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> later.redeem(created.token(), JANE));
	}

	@Test
	void aRevokedInvitationCannotBeRedeemed() {
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		this.store.revoke(created.token(), "admin");

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), JANE));
		assertThat(this.store.find(created.token())).get()
			.satisfies((invitation) -> assertThat(invitation.status(NOW)).isEqualTo(InvitationStatus.REVOKED));
	}

	@Test
	void revokingStopsEvenThePrincipalWhoAlreadyClaimedItFromRedeemingAgain() {
		// The retry window is the gap between a claim and a listener that works, and it
		// can span an outage — which is exactly when somebody might revoke. If the
		// same-principal no-op outranked revocation, revoking during that window would do
		// nothing at all: the next request would re-claim and be admitted.
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		this.store.revoke(created.token(), "admin");

		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(created.token(), JANE));
	}

	@Test
	void expiringDuringTheRetryWindowDoesNotStrandThePrincipalWhoAlreadyClaimedIt() {
		// The fix above has to stay narrow. Expiry is about invitations nobody took, and
		// USED already outranks EXPIRED in the status precedence, so a retry across the
		// expiry instant still works. Only a deliberate revocation stops it.
		Invitation created = this.store.create("jane", Duration.ofSeconds(1), List.of(), "admin");
		this.store.redeem(created.token(), JANE);
		InMemoryInvitationStore later = adopt(this.store, NOW.plusSeconds(60));

		assertThat(later.redeem(created.token(), JANE).usedBy()).isEqualTo(JANE);
	}

	@Test
	void anUnknownTokenCannotBeRedeemed() {
		assertThatExceptionOfType(InvitationStore.InvitationNotRedeemableException.class)
			.isThrownBy(() -> this.store.redeem(InvitationToken.generate(), JANE));
	}

	@Test
	void revokingAnUnknownTokenIsNotAnError() {
		// Same reason DirectoryUserStore looks an entry up before unbinding: a caller
		// tidying up should not have to know whether there is anything to tidy.
		this.store.revoke(InvitationToken.generate(), "admin");
	}

	@Test
	void revokingAClaimedInvitationDoesNotUnclaimIt() {
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(created.token(), JANE);

		this.store.revoke(created.token(), "admin");

		// Still USED, because somebody is holding the record and the audit trail has to
		// keep saying who.
		assertThat(this.store.find(created.token())).get()
			.satisfies((invitation) -> assertThat(invitation.usedBy()).isEqualTo(JANE));
	}

	@Test
	void listWithNoArgumentsReturnsEverything() {
		this.store.create("jane", null, List.of(), "admin");
		this.store.create("bob", null, List.of(), "admin");

		assertThat(this.store.list()).hasSize(2);
	}

	@Test
	void listFiltersByStatusWhichIsWhyThisSpiDoesNotInheritApprovalStoreSLimitation() {
		Invitation open = this.store.create("jane", null, List.of(), "admin");
		Invitation used = this.store.create("bob", null, List.of(), "admin");
		this.store.redeem(used.token(), BOB);
		Invitation revoked = this.store.create("carol", null, List.of(), "admin");
		this.store.revoke(revoked.token(), "admin");

		assertThat(this.store.list(InvitationStatus.OPEN)).extracting(Invitation::token).containsExactly(open.token());
		assertThat(this.store.list(InvitationStatus.USED, InvitationStatus.REVOKED)).extracting(Invitation::subjectRef)
			.containsExactlyInAnyOrder("bob", "carol");
	}

	@Test
	void listIsNewestFirstSoTheInvitationJustCreatedIsAtTheTop() {
		AtomicInteger tick = new AtomicInteger();
		InMemoryInvitationStore ticking = new InMemoryInvitationStore(new Clock() {
			@Override
			public ZoneOffset getZone() {
				return ZoneOffset.UTC;
			}

			@Override
			public Clock withZone(java.time.ZoneId zone) {
				return this;
			}

			@Override
			public Instant instant() {
				return NOW.plusSeconds(tick.getAndIncrement());
			}
		}, Duration.ofDays(14));
		ticking.create("first", null, List.of(), "admin");
		ticking.create("second", null, List.of(), "admin");

		assertThat(ticking.list()).extracting(Invitation::subjectRef).containsExactly("second", "first");
	}

	@Test
	void reInvitingCreatesANewInvitationRatherThanReopeningTheDeadOne() {
		Invitation first = this.store.create("jane", null, List.of(), "admin");
		this.store.redeem(first.token(), JANE);

		Invitation second = this.store.create("jane", null, List.of(), "admin");

		assertThat(second.token()).isNotEqualTo(first.token());
		assertThat(this.store.find(first.token())).get()
			.satisfies((invitation) -> assertThat(invitation.status(NOW)).isEqualTo(InvitationStatus.USED));
	}

	@Test
	void findByUsedByAnswersWhichRecordAPrincipalHolds() {
		Invitation invitation = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(invitation.token(), JANE);

		assertThat(this.store.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-record"));
		assertThat(this.store.findByUsedBy(BOB)).isEmpty();
	}

	@Test
	void findByUsedByFollowsAReInviteToTheNewRecord() {
		// Re-inviting is how an administrator changes what somebody holds, so the answer
		// has to be the latest claim and not whichever one the store happens to reach
		// first. The second claim has to land at a later instant for "latest" to mean
		// anything — on one fixed clock both claims share a usedAt and the question has
		// no answer, which is the contract's one soft edge.
		Invitation first = this.store.create("jane-old", null, List.of(), "admin");
		this.store.redeem(first.token(), JANE);

		InMemoryInvitationStore later = adopt(this.store, NOW.plusSeconds(60));
		Invitation second = later.create("jane-new", null, List.of(), "admin");
		later.redeem(second.token(), JANE);

		assertThat(later.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-new"));
	}

	@Test
	void findByUsedByStillFindsAClaimThatWasLaterRevoked() {
		// Revocation wins in status(), so a claimed-then-revoked invitation does not
		// appear under USED at all. An implementation filtering on that status would
		// answer "holds nothing" for somebody whose link is exactly what needs repairing.
		Invitation invitation = this.store.create("jane-record", null, List.of(), "admin");
		this.store.redeem(invitation.token(), JANE);
		this.store.revoke(invitation.token(), "admin");

		assertThat(this.store.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-record"))
			.satisfies((held) -> assertThat(held.status(NOW)).isEqualTo(InvitationStatus.REVOKED));
	}

	@Test
	void findByUsedByIsAMissForANullKeyRatherThanAnError() {
		this.store.create("jane-record", null, List.of(), "admin");

		assertThat(this.store.findByUsedBy(null)).isEmpty();
	}

	@Test
	void onlyOneOfManySimultaneousPrincipalsClaimsTheInvitation() throws Exception {
		// The case a read-then-write implementation passes every other test and fails:
		// two logins landing at once must not both claim Jane.
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		int racers = 16;
		CountDownLatch startLine = new CountDownLatch(1);
		AtomicInteger claimed = new AtomicInteger();
		ConcurrentHashMap<ApprovalKey, Boolean> winners = new ConcurrentHashMap<>();
		ExecutorService pool = Executors.newFixedThreadPool(racers);
		try {
			for (int i = 0; i < racers; i++) {
				ApprovalKey key = new ApprovalKey("google", "racer-" + i);
				pool.submit(() -> {
					try {
						startLine.await();
						this.store.redeem(created.token(), key);
						claimed.incrementAndGet();
						winners.put(key, Boolean.TRUE);
					}
					catch (InvitationStore.InvitationNotRedeemableException | InterruptedException expected) {
						// Everybody but one loses, which is the point.
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

		assertThat(claimed.get()).isOne();
		assertThat(this.store.find(created.token())).get()
			.satisfies((invitation) -> assertThat(winners).containsKey(invitation.usedBy()));
	}

	@Test
	void manySimultaneousRequestsFromTheSamePrincipalAllSucceed() throws Exception {
		// Review Focus 4, the double-click. Every one of these is the same person, so
		// every one must succeed as a no-op — refusing the second would turn a stray
		// second request into a permanent lockout.
		Invitation created = this.store.create("jane", null, List.of(), "admin");
		int attempts = 16;
		CountDownLatch startLine = new CountDownLatch(1);
		AtomicInteger succeeded = new AtomicInteger();
		ExecutorService pool = Executors.newFixedThreadPool(attempts);
		try {
			for (int i = 0; i < attempts; i++) {
				pool.submit(() -> {
					try {
						startLine.await();
						this.store.redeem(created.token(), JANE);
						succeeded.incrementAndGet();
					}
					catch (RuntimeException | InterruptedException unexpected) {
						// Left to the assertion below rather than failing on this thread.
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

		assertThat(succeeded.get()).isEqualTo(attempts);
	}

	/** Copies a store's contents into one reading a later clock. */
	private static InMemoryInvitationStore adopt(InMemoryInvitationStore source, Instant later) {
		InMemoryInvitationStore adopted = new InMemoryInvitationStore(Clock.fixed(later, ZoneOffset.UTC),
				Duration.ofDays(14));
		source.list().forEach(adopted::put);
		return adopted;
	}

}
