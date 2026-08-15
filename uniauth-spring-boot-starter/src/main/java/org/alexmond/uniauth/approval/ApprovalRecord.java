package org.alexmond.uniauth.approval;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.time.Instant;

/**
 * One principal's standing, as an approver sees it.
 *
 * @param key who this is about
 * @param mechanism which mechanism vouched for them, so a reviewer can tell a directory
 * account from a stranger with a Google login
 * @param status where they stand
 * @param firstSeen when they first authenticated
 * @param decidedAt when the decision was made, {@code null} while pending
 * @param decidedBy who decided, {@code null} while pending
 */
public record ApprovalRecord(ApprovalKey key, AuthProviderType mechanism, ApprovalStatus status, Instant firstSeen,
		Instant decidedAt, String decidedBy) {

	public ApprovalRecord decide(ApprovalStatus outcome, String approver, Instant when) {
		return new ApprovalRecord(this.key, this.mechanism, outcome, this.firstSeen, when, approver);
	}

}
