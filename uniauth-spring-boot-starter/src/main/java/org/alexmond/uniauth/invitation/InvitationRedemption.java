package org.alexmond.uniauth.invitation;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalStatus;
import org.alexmond.uniauth.approval.ApprovalStore;
import org.alexmond.uniauth.approval.PrincipalIdentity;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.ApplicationEventPublisher;

/**
 * Turns a stashed invitation token into an approval.
 *
 * <p>
 * Separate from the authorization manager so the ordering can be read in one place,
 * because the ordering is the part that matters: claim, then publish, then approve. The
 * event goes out <em>before</em> the approval is written, so a listener that throws
 * leaves the principal pending rather than admitted-and-unlinked. The claim stays, keyed
 * to this principal, so the next request retries.
 */
public class InvitationRedemption {

	private static final Logger LOGGER = LoggerFactory.getLogger(InvitationRedemption.class);

	private final InvitationStore invitations;

	private final ApprovalStore approvals;

	private final ApplicationEventPublisher events;

	private final UniAuthProperties properties;

	/**
	 * Creates the collaborator.
	 * @param invitations where invitations are claimed
	 * @param approvals where the resulting decision is written
	 * @param events publisher for the linking event
	 * @param properties supplies the fallback roles
	 */
	public InvitationRedemption(InvitationStore invitations, ApprovalStore approvals, ApplicationEventPublisher events,
			UniAuthProperties properties) {
		this.invitations = invitations;
		this.approvals = approvals;
		this.events = events;
		this.properties = properties;
	}

	/**
	 * Claims whatever invitation this session is carrying, and admits the principal.
	 *
	 * <p>
	 * Called on an authenticated request whatever the principal's current standing, not
	 * only on a first sighting. Someone whose session survived the round trip arrives
	 * {@code UNKNOWN}; someone whose pod restarted mid-login arrives {@code PENDING} and
	 * reopens the URL; someone already signed in confirms on the invitation page. All
	 * three have to work, and conditioning on {@code UNKNOWN} would break the last two.
	 * @param request the current request, whose session may carry a token
	 * @param key who is asking
	 * @param identity who the provider says they are, recorded so the decision reads like
	 * any other
	 * @param mechanism which mechanism vouched for them
	 * @return {@code true} when the principal is now approved; {@code false} when there
	 * was nothing to claim, the invitation was not claimable, or a listener refused
	 */
	public boolean admit(HttpServletRequest request, ApprovalKey key, PrincipalIdentity identity,
			AuthProviderType mechanism) {
		InvitationToken token = Invitations.pending(request);
		if (token == null) {
			return false;
		}
		Invitation claimed;
		try {
			claimed = this.invitations.redeem(token, key);
		}
		catch (InvitationStore.InvitationNotRedeemableException refused) {
			// Expired, revoked, or somebody else got there first. Drop the token so the
			// gate is not re-attempting a dead one on every request of this session.
			LOGGER.debug("An invitation could not be claimed by {}: {}", key, refused.getMessage());
			Invitations.clear(request);
			return false;
		}
		// Recorded before the event so there is something for decide() to settle, and so
		// a refusing listener leaves a visible PENDING rather than nothing at all.
		this.approvals.recordPending(key, identity, mechanism);
		try {
			this.events.publishEvent(new InvitationRedeemedEvent(key, claimed.subjectRef(), identity, token));
		}
		catch (RuntimeException failed) {
			// Deliberately not approved. The claim stands and is keyed to this principal,
			// so the next request retries and gets in once the application recovers.
			LOGGER.warn(
					"A listener refused the invitation link for {} (subjectRef '{}'); "
							+ "the principal stays pending and the next request will retry",
					key, claimed.subjectRef(), failed);
			return false;
		}
		this.approvals.decide(key, ApprovalStatus.APPROVED, "invitation:" + claimed.subjectRef(), rolesFor(claimed));
		Invitations.clear(request);
		return true;
	}

	/**
	 * The invitation's roles, or the configured defaults.
	 *
	 * <p>
	 * An approval granting nothing reproduces the bug #5 fixed: a federated principal
	 * arrives with {@code OIDC_USER} and {@code SCOPE_*} and no {@code ROLE_} at all, so
	 * they clear the gate and are then refused by every role rule in the application.
	 */
	private List<String> rolesFor(Invitation invitation) {
		return !invitation.roles().isEmpty() ? invitation.roles()
				: List.copyOf(this.properties.getApproval().getDefaultRoles());
	}

}
