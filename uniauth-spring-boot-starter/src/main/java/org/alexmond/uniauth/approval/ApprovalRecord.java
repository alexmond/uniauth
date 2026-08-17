package org.alexmond.uniauth.approval;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.time.Instant;

/**
 * One principal's standing, as an approver sees it.
 *
 * @param key who this is about, as a stable identifier
 * @param identity who that is in terms a person can judge — the key alone is often a
 * subject claim, and approving on one of those is deciding about a stranger
 * @param mechanism which mechanism vouched for them, so a reviewer can tell a directory
 * account from a stranger with a Google login
 * @param status where they stand
 * @param firstSeen when they first authenticated
 * @param decidedAt when the decision was made, {@code null} while pending
 * @param decidedBy who decided, {@code null} while pending
 */
public record ApprovalRecord(ApprovalKey key, PrincipalIdentity identity, AuthProviderType mechanism,
		ApprovalStatus status, Instant firstSeen, Instant decidedAt, String decidedBy) {

	/**
	 * Returns a copy settled with a decision, leaving this record untouched.
	 *
	 * <p>
	 * The first sighting is preserved: how long somebody waited is part of the audit
	 * trail, and overwriting it with the decision time would lose that.
	 * @param outcome {@link ApprovalStatus#APPROVED} or {@link ApprovalStatus#DENIED}
	 * @param approver name of whoever decided, for the audit trail
	 * @param when the moment of the decision
	 * @return a new record carrying the decision
	 */
	public ApprovalRecord decide(ApprovalStatus outcome, String approver, Instant when) {
		return new ApprovalRecord(this.key, this.identity, this.mechanism, outcome, this.firstSeen, when, approver);
	}

}
