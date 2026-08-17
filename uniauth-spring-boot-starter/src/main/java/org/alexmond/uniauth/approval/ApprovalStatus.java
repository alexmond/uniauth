package org.alexmond.uniauth.approval;

/**
 * Where a principal stands with the approver.
 *
 * <p>
 * {@link #UNKNOWN} is separate from {@link #PENDING} on purpose: it means nobody has ever
 * seen this principal, which is the moment a pending record gets created. Collapsing the
 * two would make "first sign-in" indistinguishable from "waiting since Tuesday".
 */
public enum ApprovalStatus {

	/** Never seen. The next authenticated request records them as {@link #PENDING}. */
	UNKNOWN,

	/** Authenticated, waiting on a decision, held at the pending page. */
	PENDING,

	/** Admitted. Takes effect on the next request, with no second sign-in. */
	APPROVED,

	/**
	 * Refused. A denied principal gets a plain 403 rather than the waiting page, because
	 * they are not waiting for anything — {@code remove} is what puts somebody back in
	 * the queue.
	 */
	DENIED

}
