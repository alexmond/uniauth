package org.alexmond.uniauth.invitation;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What an implementation gets without writing it.
 *
 * <p>
 * {@code findByUsedBy} is a default method precisely so that adding it costs nobody a
 * compile error — this SPI is the application's table, and a method it had to implement
 * would be a breaking change dressed as a feature. The store below implements only the
 * abstract methods, and only {@code list} for real, which is the whole claim.
 */
class InvitationStoreDefaultsTest {

	private static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");

	private static final ApprovalKey JANE = new ApprovalKey("google", "jane-sub");

	private static final ApprovalKey BOB = new ApprovalKey("saml", "bob-nameid");

	@Test
	void findByUsedByIsAnsweredFromListAlone() {
		InvitationStore store = new ListOnlyStore(List.of(claimed("jane-record", JANE, NOW.minusSeconds(60)),
				claimed("bob-record", BOB, NOW.minusSeconds(30))));

		assertThat(store.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-record"));
		assertThat(store.findByUsedBy(new ApprovalKey("google", "nobody"))).isEmpty();
	}

	@Test
	void theLatestClaimWinsWhateverOrderTheStoreListsThemIn() {
		// list() is documented newest-created-first, but an implementation is free to
		// return any order and a re-invite is the case that exposes it. The answer is
		// decided by usedAt, not by position.
		InvitationStore store = new ListOnlyStore(List.of(claimed("jane-new", JANE, NOW.minusSeconds(10)),
				claimed("jane-old", JANE, NOW.minusSeconds(600))));

		assertThat(store.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-new"));

		InvitationStore reversed = new ListOnlyStore(List.of(claimed("jane-old", JANE, NOW.minusSeconds(600)),
				claimed("jane-new", JANE, NOW.minusSeconds(10))));

		assertThat(reversed.findByUsedBy(JANE)).get()
			.satisfies((held) -> assertThat(held.subjectRef()).isEqualTo("jane-new"));
	}

	@Test
	void anUnclaimedInvitationIsNeverSomebodySHolding() {
		InvitationStore store = new ListOnlyStore(List.of(new Invitation(InvitationToken.generate(), "jane-record",
				List.of(), NOW, "admin", null, null, null, null)));

		assertThat(store.findByUsedBy(JANE)).isEmpty();
	}

	private static Invitation claimed(String subjectRef, ApprovalKey by, Instant at) {
		return new Invitation(InvitationToken.generate(), subjectRef, List.of(), at.minusSeconds(1), "admin", null, at,
				by, null);
	}

	/**
	 * An implementation that predates {@code findByUsedBy} and never heard of it.
	 */
	private record ListOnlyStore(List<Invitation> all) implements InvitationStore {

		@Override
		public List<Invitation> list(InvitationStatus... statuses) {
			return this.all;
		}

		@Override
		public Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy) {
			throw new UnsupportedOperationException("not needed to answer findByUsedBy");
		}

		@Override
		public Optional<Invitation> find(InvitationToken token) {
			throw new UnsupportedOperationException("not needed to answer findByUsedBy");
		}

		@Override
		public Invitation redeem(InvitationToken token, ApprovalKey admitted) {
			throw new UnsupportedOperationException("not needed to answer findByUsedBy");
		}

		@Override
		public void revoke(InvitationToken token, String revokedBy) {
			throw new UnsupportedOperationException("not needed to answer findByUsedBy");
		}

	}

}
