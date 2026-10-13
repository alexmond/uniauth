package org.alexmond.uniauth.invitation;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.PrincipalIdentity;

/**
 * Says that a principal has claimed an invitation, so the application can attach the
 * login to its own record.
 *
 * <p>
 * <strong>Published synchronously inside the authorization decision, and a listener that
 * throws fails the admission.</strong> That is an unusual contract for a Spring event and
 * it is deliberate: admitted-but-unlinked is worse than "try again", because the person
 * would be browsing as nobody, holding a session that no record backs. On a throw the
 * principal stays pending and the request is refused.
 *
 * <p>
 * Retrying is safe and is the expected recovery. The invitation stays claimed by this
 * same principal, so the next request redeems again as a no-op and admits them once the
 * application has recovered — which is why one-use is keyed by principal rather than by
 * request.
 *
 * <p>
 * The link is also durable without any listener at all: {@code Invitation.usedBy} records
 * which key claimed which {@code subjectRef}, permanently. An application that would
 * rather query the store than listen can.
 *
 * @param key the approval key the principal was admitted under —
 * {@code (provider, subject)}
 * @param subjectRef the application's own identifier for the person, straight off the
 * invitation and never interpreted by UniAuth
 * @param identity who the provider says they are, for a listener that wants to store a
 * display name or address alongside the link
 * @param token the invitation claimed, for the application's own audit trail
 */
public record InvitationRedeemedEvent(ApprovalKey key, String subjectRef, PrincipalIdentity identity,
		InvitationToken token) {
}
