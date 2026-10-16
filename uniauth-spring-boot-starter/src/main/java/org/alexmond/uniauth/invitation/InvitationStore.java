package org.alexmond.uniauth.invitation;

import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.alexmond.uniauth.approval.ApprovalKey;

/**
 * Where invitations live.
 *
 * <p>
 * An SPI, on the same bargain as {@code ApprovalStore}: UniAuth owns the flow and never
 * the table. Owning one would force Spring Data, a schema and a migration story onto
 * every application that only wanted a login page.
 *
 * <p>
 * Unlike {@code ApprovalStore}, this interface can enumerate from the start. That gap in
 * the approval SPI is real (#10), but a sibling does not inherit it — an administrator
 * cannot manage invitations they cannot list.
 *
 * <p>
 * Implementations must be safe for concurrent use.
 */
public interface InvitationStore {

	/**
	 * Mints an invitation for a person the application already holds a record for.
	 * @param subjectRef the application's own identifier for that person. UniAuth never
	 * interprets it; it is handed back on redemption so the application can do the
	 * linking
	 * @param ttl how long it stays usable, or {@code null} for the configured
	 * {@code default-expiry}. Must be positive if given
	 * @param roles granted on admission, or empty to fall back to
	 * {@code uniauth.approval.default-roles}. Null and blank entries are dropped, because
	 * they would otherwise reach the authorities filter and be granted as
	 * {@code ROLE_null}
	 * @param createdBy who is inviting, for the audit trail
	 * @return the new invitation, including its token
	 * @throws IllegalArgumentException if {@code subjectRef} is blank or {@code ttl} is
	 * not positive
	 */
	Invitation create(String subjectRef, Duration ttl, List<String> roles, String createdBy);

	/**
	 * Looks an invitation up.
	 * @param token the token presented
	 * @return the invitation, or empty when nothing matches. An unrecognised token is a
	 * miss rather than an error: most of them are typos and scanners
	 */
	Optional<Invitation> find(InvitationToken token);

	/**
	 * Atomically claims an OPEN invitation for this principal.
	 *
	 * <p>
	 * <strong>This is the only place one-use is enforced, and it must be a
	 * compare-and-set rather than a read-then-write.</strong> A read-then-write passes
	 * every single-threaded test and admits two people under load; two simultaneous
	 * logins must not both claim Jane.
	 *
	 * <p>
	 * <strong>A revoked invitation is refused even to the principal who already claimed
	 * it.</strong> Revocation outranks the no-op below, because it is the one refusal
	 * somebody chose deliberately and the retry window it has to override can span an
	 * outage — which is exactly when it gets used.
	 *
	 * <p>
	 * One-use means one <em>principal</em>, not one request. Claiming again with the
	 * <em>same</em> key succeeds and is a no-op — which is what lets a transient failure
	 * in the application be retried, rather than stranding the invited person with a URL
	 * that can never work again. Claiming with a different key fails.
	 * @param token the token presented
	 * @param admitted the principal claiming it
	 * @return the claimed invitation, carrying {@code usedBy} and {@code usedAt}
	 * @throws InvitationNotRedeemableException if there is no such invitation, or it is
	 * expired or revoked, or another principal already claimed it
	 */
	Invitation redeem(InvitationToken token, ApprovalKey admitted);

	/**
	 * Withdraws an invitation.
	 *
	 * <p>
	 * Revoking one already claimed does not unclaim it: somebody is holding the record,
	 * and the audit trail has to keep saying who.
	 * @param token the token to withdraw; withdrawing an unknown one is not an error
	 * @param revokedBy who withdrew it, for the audit trail
	 */
	void revoke(InvitationToken token, String revokedBy);

	/**
	 * Every invitation in the given states, newest first.
	 * @param statuses the states wanted, or none at all for every invitation
	 * @return the matching invitations, newest first so the one just created is at the
	 * top
	 */
	List<Invitation> list(InvitationStatus... statuses);

	/**
	 * Which record a login holds, if any.
	 *
	 * <p>
	 * {@link Invitation#usedBy()} makes the link durable without the application storing
	 * anything, which is why {@code ApprovalRecord} gains no {@code subjectRef} field.
	 * But durable is not reachable: the only way to ask was to list every invitation and
	 * filter, so an application wanting the link on a later request — or repairing its
	 * own table after a listener failed — had no question to ask (#36).
	 *
	 * <p>
	 * A default method on purpose. This interface is the application's table, so one it
	 * had to implement would be a breaking change dressed as a feature, and the answer is
	 * derivable from {@code list} for everybody. An implementation backed by a database
	 * should override it with the obvious indexed query rather than listing the table.
	 *
	 * <p>
	 * The latest claim wins, by {@code usedAt} and then by {@code createdAt}. Re-inviting
	 * is the only way to change what somebody holds, so after one there are two
	 * invitations naming the same principal and the current answer is the newer. Two
	 * claims identical in both instants are a tie this cannot break, and it returns
	 * either — worth knowing rather than hiding, though it takes one principal claiming
	 * two invitations within the same clock tick.
	 *
	 * <p>
	 * A claim that was later revoked is still returned: revocation outranks use in
	 * {@link Invitation#status(java.time.Instant)}, so filtering on {@code USED} would
	 * answer "holds nothing" for precisely the person whose link needs attention. Read
	 * {@code status(now)} on what comes back and decide.
	 * @param admitted the principal to ask about; {@code null} is a miss, not an error
	 * @return their most recent claim, or empty if they have never claimed one
	 */
	default Optional<Invitation> findByUsedBy(ApprovalKey admitted) {
		if (admitted == null) {
			return Optional.empty();
		}
		Comparator<Invitation> byClaim = Comparator
			.comparing(Invitation::usedAt, Comparator.nullsFirst(Comparator.naturalOrder()))
			.thenComparing(Invitation::createdAt, Comparator.nullsFirst(Comparator.naturalOrder()));
		return list().stream().filter((invitation) -> admitted.equals(invitation.usedBy())).max(byClaim);
	}

	/**
	 * Thrown when an invitation cannot be claimed.
	 *
	 * <p>
	 * Deliberately one exception rather than four. The caller's reaction is identical in
	 * every case — fall through to the ordinary approval gate — and distinguishing them
	 * would tell whoever presented the token more about the store than they need.
	 */
	class InvitationNotRedeemableException extends RuntimeException {

		/**
		 * @param message why it could not be claimed, for the log and not for the caller
		 */
		public InvitationNotRedeemableException(String message) {
			super(message);
		}

	}

}
