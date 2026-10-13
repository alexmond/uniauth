package org.alexmond.uniauth.invitation;

import java.time.Instant;
import java.util.List;

import org.alexmond.uniauth.approval.ApprovalKey;

/**
 * One invitation: who it names, who may use it, and what became of it.
 *
 * <p>
 * {@code usedBy} is what makes the link durable without anybody listening for the event.
 * It records permanently that a given {@link ApprovalKey} claimed a given
 * {@code subjectRef}, so {@code (google, sub) -> Jane} is recoverable by querying the
 * store. That is why {@code ApprovalRecord} does not gain a {@code subjectRef} field:
 * widening it would be breaking for every {@code ApprovalStore} implementor, which #5
 * already did once.
 *
 * @param token the credential, which is also the store's key
 * @param subjectRef the application's own identifier for the person — a row id, a
 * username, whatever the application already calls Jane. UniAuth never interprets it
 * @param roles what the invited principal is granted on admission, empty to fall back to
 * {@code uniauth.approval.default-roles}
 * @param createdAt when it was minted
 * @param createdBy who minted it, for the audit trail
 * @param expiresAt when it stops working, or {@code null} to never expire
 * @param usedAt when it was claimed, {@code null} while unclaimed
 * @param usedBy which principal claimed it, {@code null} while unclaimed. One-use means
 * one <em>principal</em>: re-claiming with this same key is a no-op, so a transient
 * failure in the application does not strand the invited person with a dead URL
 * @param revokedAt when a person withdrew it, {@code null} otherwise
 */
public record Invitation(InvitationToken token, String subjectRef, List<String> roles, Instant createdAt,
		String createdBy, Instant expiresAt, Instant usedAt, ApprovalKey usedBy, Instant revokedAt) {

	public Invitation {
		roles = (roles != null) ? List.copyOf(roles) : List.of();
	}

	/**
	 * Where this invitation stands, as of a given moment.
	 *
	 * <p>
	 * Precedence matters when more than one applies. Revocation wins, because it is the
	 * only status a person chose deliberately and the only one they will go looking for
	 * afterwards. Use beats expiry, because "expired" would hide that somebody is already
	 * holding the record.
	 * @param now the moment to judge against, passed in rather than read so a test can
	 * assert on boundaries without sleeping
	 * @return the status, never {@code null}
	 */
	public InvitationStatus status(Instant now) {
		if (this.revokedAt != null) {
			return InvitationStatus.REVOKED;
		}
		if (this.usedAt != null) {
			return InvitationStatus.USED;
		}
		// Inclusive: at the expiry instant it is already dead, matching JWT exp, HTTP
		// Expires and cookie max-age rather than inventing a convention of our own.
		if (this.expiresAt != null && !now.isBefore(this.expiresAt)) {
			return InvitationStatus.EXPIRED;
		}
		return InvitationStatus.OPEN;
	}

}
