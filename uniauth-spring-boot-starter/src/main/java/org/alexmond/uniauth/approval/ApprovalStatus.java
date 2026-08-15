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

	UNKNOWN,

	PENDING,

	APPROVED,

	DENIED

}
