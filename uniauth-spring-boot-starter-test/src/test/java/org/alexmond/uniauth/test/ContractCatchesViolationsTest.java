package org.alexmond.uniauth.test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.PrincipalIdentity;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.alexmond.uniauth.invitation.Invitation;
import org.alexmond.uniauth.invitation.InvitationStatus;
import org.alexmond.uniauth.invitation.InvitationStore;
import org.alexmond.uniauth.invitation.InvitationToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.testkit.engine.EngineTestKit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proof that the contract fails a store that breaks the rules.
 *
 * <p>
 * Without this file the kit is unfalsifiable. Every suite in it passes against the two
 * shipped implementations, which demonstrates that the rules are satisfiable and nothing
 * whatever about whether they are <em>enforced</em> — and the defect this kit exists for
 * is precisely the one nobody catches by reading: a {@code redeem} that reads, decides,
 * then writes. It passes every single-threaded case and binds two people to one record
 * under load.
 *
 * <p>
 * So each case below runs a contract suite against a store broken in one specific way,
 * and asserts the suite reports that failure. The broken stores are correct in every
 * other respect, so a pass here means the contract isolated the rule rather than noticing
 * that something somewhere was wrong.
 */
class ContractCatchesViolationsTest {

	@Test
	@DisplayName("a read-then-write redeem is caught, which is the whole reason this kit exists")
	void readThenWriteIsCaught() {
		EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectMethod(ReadThenWrite.class,
					"onlyOneOfManySimultaneousPrincipalsClaimsTheInvitation"))
			.execute()
			.testEvents()
			.assertStatistics((stats) -> stats.failed(1));
	}

	@Test
	@DisplayName("a store that ignores revocation is caught by the two cases that matter")
	void ignoredRevocationIsCaught() {
		List<String> failed = EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectClass(IgnoresRevocation.class))
			.execute()
			.testEvents()
			.failed()
			.stream()
			.map((event) -> event.getTestDescriptor().getDisplayName())
			.toList();

		// Named rather than counted, and the count is worth knowing: of the five cases
		// that touch revocation, three still pass against a store that ignores it —
		// because they assert what revocation leaves ALONE (the claim survives, an
		// unknown token is no error, the link is still findable). Only these two assert
		// what it must CHANGE, so these two are the kit's real guard.
		assertThat(failed).containsExactlyInAnyOrder("aRevokedInvitationCannotBeRedeemed()",
				"revokingOutranksTheRetryAndRefusesEvenThePrincipalWhoAlreadyClaimedIt()");
	}

	@Test
	@DisplayName("a store that reads the clock once at construction is caught")
	void aFrozenClockIsCaught() {
		EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectMethod(FreezesTheClock.class, "anExpiredInvitationCannotBeRedeemed"))
			.execute()
			.testEvents()
			.assertStatistics((stats) -> stats.failed(1));
	}

	@Test
	@DisplayName("a store that lets a second principal take a claimed invitation is caught")
	void aStolenClaimIsCaught() {
		EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectMethod(LetsAnybodyClaim.class,
					"aDifferentPrincipalCannotClaimAnInvitationAlreadyTaken"))
			.execute()
			.testEvents()
			.assertStatistics((stats) -> stats.failed(1));
	}

	@Test
	@DisplayName("a store that kills the token on first claim is caught")
	void aSingleUseTokenIsCaught() {
		// The mistake a careful implementor is most likely to make, because "one use"
		// sounds like it means one request. It strands the invited person after one
		// transient listener failure.
		EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectMethod(OneRequestOnly.class, "oneUseMeansOnePersonAndNotOneRequest"))
			.execute()
			.testEvents()
			.assertStatistics((stats) -> stats.failed(1));
	}

	@Test
	@DisplayName("a store whose list() still answers only the queue is caught")
	void aQueueOnlyListIsCaught() {
		// The migration mistake to expect: list() wired to the query pending() already
		// used, which compiles, passes every pre-existing case, and leaves the access
		// list the method was added for showing nobody (#10).
		EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectMethod(ListsOnlyPending.class,
					"listHoldsEverybodyTheStoreKnowsWhateverTheirStanding"))
			.execute()
			.testEvents()
			.assertStatistics((stats) -> stats.failed(1));
	}

	@Test
	@DisplayName("a store that ignores the status filter is caught")
	void anIgnoredFilterIsCaught() {
		List<String> failed = EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectClass(IgnoresTheFilter.class))
			.execute()
			.testEvents()
			.failed()
			.stream()
			.map((event) -> event.getTestDescriptor().getDisplayName())
			.toList();

		// Named rather than counted, for the same reason as the revocation cases above:
		// a store that hands back everything regardless of the filter also breaks the
		// queue, because pending() reads through list(). That second failure is the one
		// an implementor will actually notice, since it empties nothing and instead puts
		// approved people back on the approvals page.
		//
		// Note which case does NOT fire: listHoldsEverybody... passes, correctly — a
		// store that ignores the filter answers an unfiltered list exactly right. The
		// filter rules are what separate the two flaws.
		assertThat(failed).contains("listFiltersToTheStandingsAsked()",
				"listingUnknownHoldsNobodyBecauseNoRecordIsEverStoredThatWay()", "pendingHoldsOnlyThoseStillWaiting()");
	}

	@Test
	@DisplayName("a store whose own pending() disagrees with its list() is caught")
	void aDisagreeingPendingIsCaught() {
		// Overriding pending() stays supported — a table indexed for the queue should go
		// on using that index — so the contract has to check the two agree. They drift
		// the moment one of them is changed and the other is not.
		EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectMethod(PendingDisagreesWithList.class,
					"pendingAnswersExactlyWhatListOfPendingDoes"))
			.execute()
			.testEvents()
			.assertStatistics((stats) -> stats.failed(1));
	}

	@Test
	@DisplayName("a store that lists newest first is caught")
	void aReversedOrderIsCaught() {
		// The single guard on ordering, and worth knowing as such: of the eighteen
		// approval cases exactly one fails against a store that reverses the order,
		// because every other assertion either ignores order or holds one element. The
		// older queue case cannot help — it asserts containsExactly on a list of one.
		EngineTestKit.engine("junit-jupiter")
			.selectors(DiscoverySelectors.selectMethod(NewestFirst.class, "listIsOldestFirstThroughoutTheInterface"))
			.execute()
			.testEvents()
			.assertStatistics((stats) -> stats.failed(1));
	}

	// The suites. Each points the contract at one broken store.

	static class ReadThenWrite extends InvitationStoreContract {

		@Override
		protected InvitationStore createStore(Clock clock) {
			return new BrokenInvitationStore(clock, BrokenInvitationStore.Flaw.READ_THEN_WRITE);
		}

	}

	static class IgnoresRevocation extends InvitationStoreContract {

		@Override
		protected InvitationStore createStore(Clock clock) {
			return new BrokenInvitationStore(clock, BrokenInvitationStore.Flaw.IGNORES_REVOCATION);
		}

	}

	static class FreezesTheClock extends InvitationStoreContract {

		@Override
		protected InvitationStore createStore(Clock clock) {
			return new BrokenInvitationStore(clock, BrokenInvitationStore.Flaw.FREEZES_THE_CLOCK);
		}

	}

	static class LetsAnybodyClaim extends InvitationStoreContract {

		@Override
		protected InvitationStore createStore(Clock clock) {
			return new BrokenInvitationStore(clock, BrokenInvitationStore.Flaw.LETS_ANYBODY_CLAIM);
		}

	}

	static class OneRequestOnly extends InvitationStoreContract {

		@Override
		protected InvitationStore createStore(Clock clock) {
			return new BrokenInvitationStore(clock, BrokenInvitationStore.Flaw.ONE_REQUEST_ONLY);
		}

	}

	/**
	 * A store that is correct apart from one chosen flaw.
	 *
	 * <p>
	 * Correct elsewhere on purpose: a store broken in several ways would fail the suite
	 * for reasons that prove nothing about the rule under examination.
	 */
	private static final class BrokenInvitationStore implements InvitationStore {

		enum Flaw {

			/** Reads, decides, then writes — with the window held open. */
			READ_THEN_WRITE,
			/** Accepts revoke and does nothing with it. */
			IGNORES_REVOCATION,
			/** Reads the clock once, at construction. */
			FREEZES_THE_CLOCK,
			/** Lets a second principal take an invitation already claimed. */
			LETS_ANYBODY_CLAIM,
			/** Treats one use as one request, so a retry is refused. */
			ONE_REQUEST_ONLY

		}

		private final Map<InvitationToken, Invitation> invitations = new ConcurrentHashMap<>();

		private final Clock clock;

		private final Instant frozen;

		private final Flaw flaw;

		BrokenInvitationStore(Clock clock, Flaw flaw) {
			this.clock = clock;
			this.frozen = clock.instant();
			this.flaw = flaw;
		}

		private Instant now() {
			return (this.flaw == Flaw.FREEZES_THE_CLOCK) ? this.frozen : this.clock.instant();
		}

		@Override
		public Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy) {
			if (subjectRef == null || subjectRef.isBlank()) {
				throw new IllegalArgumentException("An invitation needs a subjectRef");
			}
			if (ttl != null && !ttl.isPositive()) {
				throw new IllegalArgumentException("A ttl must be positive");
			}
			Instant now = now();
			Duration life = (ttl != null) ? ttl : Duration.ofDays(14);
			Invitation created = new Invitation(InvitationToken.generate(), subjectRef, roles, now, createdBy,
					now.plus(life), null, null, null);
			this.invitations.put(created.token(), created);
			return created;
		}

		@Override
		public Optional<Invitation> find(InvitationToken token) {
			return Optional.ofNullable(this.invitations.get(token));
		}

		@Override
		public Invitation redeem(InvitationToken token, ApprovalKey admitted) {
			if (this.flaw == Flaw.READ_THEN_WRITE) {
				return readThenWrite(token, admitted);
			}
			// Atomic for every other flaw, and that matters: a store broken in two ways
			// fails cases that prove nothing about the rule under examination. The first
			// draft of this class used get-then-put throughout, and the concurrency case
			// duly failed every variant — the kit catching a defect in its own fixture.
			java.util.concurrent.atomic.AtomicReference<Invitation> granted = new java.util.concurrent.atomic.AtomicReference<>();
			this.invitations.compute(token, (unused, existing) -> {
				if (existing == null) {
					return null;
				}
				granted.set(claimIfAllowed(existing, admitted));
				return (granted.get() != null) ? granted.get() : existing;
			});
			Invitation claimed = granted.get();
			if (claimed == null) {
				throw new InvitationNotRedeemableException("not open to this principal");
			}
			return claimed;
		}

		/**
		 * The claim decision, with this store's one flaw folded in.
		 * @param existing what the store holds
		 * @param admitted who is claiming
		 * @return the claimed invitation, or {@code null} to refuse
		 */
		private Invitation claimIfAllowed(Invitation existing, ApprovalKey admitted) {
			if (this.flaw != Flaw.IGNORES_REVOCATION && existing.revokedAt() != null) {
				return null;
			}
			if (admitted.equals(existing.usedBy())) {
				return (this.flaw != Flaw.ONE_REQUEST_ONLY) ? existing : null;
			}
			if (existing.usedAt() != null && this.flaw != Flaw.LETS_ANYBODY_CLAIM) {
				return null;
			}
			if (existing.usedAt() == null && existing.status(now()) == InvitationStatus.EXPIRED) {
				return null;
			}
			return new Invitation(existing.token(), existing.subjectRef(), existing.roles(), existing.createdAt(),
					existing.createdBy(), existing.expiresAt(), now(), admitted, existing.revokedAt());
		}

		/**
		 * Read, decide, write — with the window held open so the race is a certainty
		 * rather than a coin toss. A real implementation's window is a round trip to its
		 * database, which is wider than this.
		 * @param token the invitation
		 * @param admitted who is claiming
		 * @return the claim this thread believes it made
		 */
		private Invitation readThenWrite(InvitationToken token, ApprovalKey admitted) {
			Invitation existing = this.invitations.get(token);
			if (existing == null) {
				throw new InvitationNotRedeemableException("unknown");
			}
			Invitation claimed = claimIfAllowed(existing, admitted);
			if (claimed == null) {
				throw new InvitationNotRedeemableException("not open to this principal");
			}
			try {
				Thread.sleep(5);
			}
			catch (InterruptedException interrupted) {
				Thread.currentThread().interrupt();
			}
			this.invitations.put(claimed.token(), claimed);
			return claimed;
		}

		@Override
		public void revoke(InvitationToken token, String revokedBy) {
			if (this.flaw == Flaw.IGNORES_REVOCATION) {
				return;
			}
			this.invitations.computeIfPresent(token,
					(unused, existing) -> new Invitation(existing.token(), existing.subjectRef(), existing.roles(),
							existing.createdAt(), existing.createdBy(), existing.expiresAt(), existing.usedAt(),
							existing.usedBy(), now()));
		}

		@Override
		public List<Invitation> list(InvitationStatus... statuses) {
			List<InvitationStatus> wanted = (statuses.length > 0) ? List.of(statuses)
					: List.of(InvitationStatus.values());
			Instant now = now();
			return this.invitations.values()
				.stream()
				.filter((invitation) -> wanted.contains(invitation.status(now)))
				.sorted(Comparator.comparing(Invitation::createdAt).reversed())
				.toList();
		}

	}

	// The approval suites. Each points the contract at one broken store.

	static class ListsOnlyPending extends ApprovalStoreContract {

		@Override
		protected ApprovalStore createStore(Clock clock) {
			return new BrokenApprovalStore(clock, BrokenApprovalStore.Flaw.LISTS_ONLY_PENDING);
		}

	}

	static class IgnoresTheFilter extends ApprovalStoreContract {

		@Override
		protected ApprovalStore createStore(Clock clock) {
			return new BrokenApprovalStore(clock, BrokenApprovalStore.Flaw.IGNORES_THE_FILTER);
		}

	}

	static class PendingDisagreesWithList extends ApprovalStoreContract {

		@Override
		protected ApprovalStore createStore(Clock clock) {
			return new BrokenApprovalStore(clock, BrokenApprovalStore.Flaw.PENDING_DISAGREES);
		}

	}

	static class NewestFirst extends ApprovalStoreContract {

		@Override
		protected ApprovalStore createStore(Clock clock) {
			return new BrokenApprovalStore(clock, BrokenApprovalStore.Flaw.NEWEST_FIRST);
		}

	}

	/**
	 * An {@link ApprovalStore} that is correct apart from one chosen flaw.
	 *
	 * <p>
	 * Every flaw here is in enumeration, because enumeration is what the interface gained
	 * (#10) and the rest of the contract was already falsified by the invitation stores
	 * above. Correct elsewhere on purpose, for the same reason as those.
	 */
	private static final class BrokenApprovalStore implements ApprovalStore {

		enum Flaw {

			/** list() answers the queue, which is the query it was migrated from. */
			LISTS_ONLY_PENDING,
			/** Hands back every record whatever was asked for. */
			IGNORES_THE_FILTER,
			/** Keeps its own pending() query, and that query disagrees. */
			PENDING_DISAGREES,
			/** Lists newest first, reversing the published queue order. */
			NEWEST_FIRST

		}

		private final Map<ApprovalKey, ApprovalRecord> records = new ConcurrentHashMap<>();

		private final Clock clock;

		private final Flaw flaw;

		BrokenApprovalStore(Clock clock, Flaw flaw) {
			this.clock = clock;
			this.flaw = flaw;
		}

		@Override
		public ApprovalStatus statusOf(ApprovalKey key) {
			ApprovalRecord record = this.records.get(key);
			return (record != null) ? record.status() : ApprovalStatus.UNKNOWN;
		}

		@Override
		public ApprovalRecord recordPending(ApprovalKey key, PrincipalIdentity identity, AuthProviderType mechanism) {
			return this.records.computeIfAbsent(key, (absent) -> new ApprovalRecord(absent, identity, mechanism,
					ApprovalStatus.PENDING, this.clock.instant(), null, null, List.of()));
		}

		@Override
		public List<ApprovalRecord> list(ApprovalStatus... statuses) {
			List<ApprovalStatus> wanted = switch (this.flaw) {
				case LISTS_ONLY_PENDING -> List.of(ApprovalStatus.PENDING);
				case IGNORES_THE_FILTER -> List.of(ApprovalStatus.values());
				default -> (statuses.length > 0) ? List.of(statuses) : List.of(ApprovalStatus.values());
			};
			Comparator<ApprovalRecord> order = Comparator.comparing(ApprovalRecord::firstSeen);
			return this.records.values()
				.stream()
				.filter((record) -> wanted.contains(record.status()))
				.sorted((this.flaw == Flaw.NEWEST_FIRST) ? order.reversed() : order)
				.toList();
		}

		@Override
		public List<ApprovalRecord> pending() {
			if (this.flaw != Flaw.PENDING_DISAGREES) {
				return ApprovalStore.super.pending();
			}
			// Plausible rather than absurd: somebody who reads DENIED as "still to be
			// dealt with" and leaves them on the queue page.
			return list(ApprovalStatus.PENDING, ApprovalStatus.DENIED);
		}

		@Override
		public Optional<ApprovalRecord> find(ApprovalKey key) {
			return Optional.ofNullable(this.records.get(key));
		}

		@Override
		public void decide(ApprovalKey key, ApprovalStatus outcome, String approver, List<String> roles) {
			if (outcome != ApprovalStatus.APPROVED && outcome != ApprovalStatus.DENIED) {
				throw new IllegalArgumentException("A decision must be APPROVED or DENIED, not " + outcome);
			}
			this.records.computeIfPresent(key,
					(unused, record) -> record.decide(outcome, approver, this.clock.instant(), roles));
		}

		@Override
		public void remove(ApprovalKey key) {
			this.records.remove(key);
		}

	}

}
