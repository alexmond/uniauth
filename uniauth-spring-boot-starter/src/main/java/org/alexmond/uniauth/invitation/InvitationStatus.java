package org.alexmond.uniauth.invitation;

/**
 * Where an invitation stands, derived from its own timestamps rather than stored.
 *
 * <p>
 * Stored status would go stale the moment an invitation expired with nobody looking at
 * it, and the store would then need a sweeper to stay honest.
 */
public enum InvitationStatus {

	/**
	 * Not yet claimed, not expired, not revoked. The only status that may be redeemed.
	 */
	OPEN,

	/** Claimed. One principal holds it, permanently — see {@code Invitation.usedBy}. */
	USED,

	/**
	 * Past its expiry, unclaimed. Re-inviting creates a new invitation, never reopens
	 * this one.
	 */
	EXPIRED,

	/**
	 * Withdrawn by a person. Beats every other status, because it is the only deliberate
	 * one.
	 */
	REVOKED

}
