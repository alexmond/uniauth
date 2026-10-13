package org.alexmond.uniauth.invitation;

import java.time.Instant;
import java.util.List;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * The value types. Status is derived rather than stored, because a stored status goes
 * stale the moment an invitation expires with nobody looking at it.
 */
class InvitationTest {

	private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

	private static final ApprovalKey JANE = new ApprovalKey("google", "1234567890");

	@Test
	void aFreshInvitationIsOpen() {
		assertThat(invitation(null, null, null).status(NOW)).isEqualTo(InvitationStatus.OPEN);
	}

	@Test
	void anInvitationPastItsExpiryIsExpired() {
		Invitation past = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100), "admin",
				NOW.minusSeconds(1), null, null, null);

		assertThat(past.status(NOW)).isEqualTo(InvitationStatus.EXPIRED);
	}

	@Test
	void anInvitationIsExpiredAtTheInstantItExpiresAndOpenUpToIt() {
		// Inclusive, matching JWT exp, HTTP Expires and cookie max-age: "expires at T"
		// means dead at T, not dead after it. A fourteen-day invitation is then good for
		// exactly fourteen days rather than fourteen days and one nanosecond.
		Invitation edge = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100), "admin",
				NOW, null, null, null);

		assertThat(edge.status(NOW)).isEqualTo(InvitationStatus.EXPIRED);
		assertThat(edge.status(NOW.minusNanos(1))).isEqualTo(InvitationStatus.OPEN);
	}

	@Test
	void aClaimedInvitationIsUsed() {
		assertThat(invitation(NOW.minusSeconds(10), JANE, null).status(NOW)).isEqualTo(InvitationStatus.USED);
	}

	@Test
	void aRevokedInvitationIsRevoked() {
		assertThat(invitation(null, null, NOW.minusSeconds(10)).status(NOW)).isEqualTo(InvitationStatus.REVOKED);
	}

	@Test
	void revocationBeatsExpiryAndUse() {
		// Three could apply at once. Revoked wins, because it is the only one a person
		// decided deliberately and the only one they will look for afterwards.
		Invitation everything = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100),
				"admin", NOW.minusSeconds(50), NOW.minusSeconds(60), JANE, NOW.minusSeconds(40));

		assertThat(everything.status(NOW)).isEqualTo(InvitationStatus.REVOKED);
	}

	@Test
	void useBeatsExpiry() {
		// Claimed on Tuesday, expired on Wednesday: it was used, and saying "expired"
		// would hide that somebody is now holding the record.
		Invitation claimedThenExpired = new Invitation(InvitationToken.generate(), "jane", List.of(),
				NOW.minusSeconds(100), "admin", NOW.minusSeconds(50), NOW.minusSeconds(60), JANE, null);

		assertThat(claimedThenExpired.status(NOW)).isEqualTo(InvitationStatus.USED);
	}

	@Test
	void anInvitationWithNoExpiryNeverExpires() {
		Invitation forever = new Invitation(InvitationToken.generate(), "jane", List.of(), NOW.minusSeconds(100),
				"admin", null, null, null, null);

		assertThat(forever.status(NOW.plusSeconds(99999999L))).isEqualTo(InvitationStatus.OPEN);
	}

	@Test
	void rolesAreCopiedAndNeverNull() {
		Invitation nullRoles = new Invitation(InvitationToken.generate(), "jane", null, NOW, "admin", null, null, null,
				null);

		assertThat(nullRoles.roles()).isEmpty();
	}

	@Test
	void aTokenIsUrlSafeAndCarriesAtLeast128Bits() {
		String value = InvitationToken.generate().value();

		// Base64url of 16 bytes is 22 characters; anything shorter is not 128 bits.
		assertThat(value).hasSizeGreaterThanOrEqualTo(22).matches("[A-Za-z0-9_-]+");
	}

	@Test
	void twoGeneratedTokensDiffer() {
		assertThat(InvitationToken.generate()).isNotEqualTo(InvitationToken.generate());
	}

	@Test
	void tokensWithTheSameValueAreEqualSoTheyWorkAsMapKeys() {
		InvitationToken token = InvitationToken.generate();

		assertThat(InvitationToken.of(token.value())).isEqualTo(token).hasSameHashCodeAs(token);
	}

	@Test
	void aBlankTokenIsRejected() {
		assertThatIllegalArgumentException().isThrownBy(() -> InvitationToken.of("  "));
	}

	@Test
	void aTokenDoesNotPrintItsOwnValue() {
		// It is a bearer credential, and the one place it reliably leaks is a log line
		// that interpolated an object.
		InvitationToken token = InvitationToken.generate();

		assertThat(token.toString()).doesNotContain(token.value());
	}

	private static Invitation invitation(Instant usedAt, ApprovalKey usedBy, Instant revokedAt) {
		return new Invitation(InvitationToken.generate(), "jane", List.of("USER"), NOW.minusSeconds(100), "admin",
				NOW.plusSeconds(100), usedAt, usedBy, revokedAt);
	}

}
