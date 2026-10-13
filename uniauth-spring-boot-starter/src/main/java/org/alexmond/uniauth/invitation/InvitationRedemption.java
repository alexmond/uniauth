package org.alexmond.uniauth.invitation;

import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

import org.alexmond.uniauth.approval.ApprovalKey;
import org.alexmond.uniauth.approval.ApprovalRecord;
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

	/**
	 * Recorded as the approver when {@code invite-only} refuses somebody by itself.
	 *
	 * <p>
	 * Named rather than inlined because two classes have to agree on it: the gate writes
	 * it, and this class reads it to tell an automatic refusal from one a person made. An
	 * invitation may override the first and must never override the second.
	 */
	public static final String INVITE_ONLY = "invite-only";

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
	 * <p>
	 * A refusal somebody has already recorded is honoured, and is re-checked after the
	 * listener returns. The two are still separate calls, so a refusal landing in the gap
	 * between the second check and the write would be overwritten; closing that entirely
	 * needs a compare-and-set, and widening {@code ApprovalStore} for it would break
	 * every implementation. A durable store closes it by running these writes in one
	 * transaction.
	 * @return {@code true} when the principal is now approved; {@code false} when there
	 * was nothing to claim, the invitation was not claimable, a listener refused, or
	 * somebody has refused this principal
	 */
	public boolean admit(HttpServletRequest request, ApprovalKey key, PrincipalIdentity identity,
			AuthProviderType mechanism) {
		InvitationToken token = Invitations.pending(request);
		if (token == null) {
			return false;
		}
		if (refusedByAPerson(key)) {
			// Ahead of the claim, so a refused principal does not burn the invitation
			// either — it stays open for whoever it was meant for.
			LOGGER.warn("{} holds an invitation but was refused by {}; the refusal stands", key,
					this.approvals.find(key).map(ApprovalRecord::decidedBy).orElse("an approver"));
			Invitations.clear(request);
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
		Optional<ApprovalRecord> settled = settledByAPerson(key);
		if (settled.isPresent()) {
			// Checked after the listener, because it is the application's own callback
			// and
			// may have taken any amount of time — easily long enough for somebody to
			// decide in between. Their decision stands whichever way it went: an approver
			// who granted narrower roles than the invitation carries meant the narrower
			// ones, and a refusal is a refusal. The link has been made either way, which
			// is what was actually outstanding.
			//
			// This does not make the pair atomic; it shrinks the window from an unbounded
			// callback to two adjacent statements, which is as far as this can go without
			// a compare-and-set on ApprovalStore, and widening that SPI would break every
			// implementation of it. A durable store closes the remainder by running this
			// method's writes in one transaction.
			ApprovalStatus standing = settled.get().status();
			LOGGER.info("{} was already decided ({}) by {}; the invitation linked them and that decision stands", key,
					standing, settled.get().decidedBy());
			Invitations.clear(request);
			return standing == ApprovalStatus.APPROVED;
		}
		this.approvals.decide(key, ApprovalStatus.APPROVED, "invitation:" + claimed.subjectRef(), rolesFor(claimed));
		Invitations.clear(request);
		return true;
	}

	/**
	 * Whether somebody has deliberately refused this principal.
	 *
	 * <p>
	 * A {@code DENIED} record is reached two ways, and they must not be treated alike. An
	 * approver looking at a pending record and refusing it is a decision an invitation
	 * must never silently revert — and the moment it is most likely to happen is the
	 * retry window, where a claim whose listener threw leaves exactly the pending record
	 * an approver would act on.
	 *
	 * <p>
	 * {@code invite-only} refusing a first-time visitor is not that. Under that setting
	 * every stranger is recorded {@code DENIED}, so somebody who signed in before opening
	 * their link would be locked out for good if an invitation could not override it.
	 */
	private boolean refusedByAPerson(ApprovalKey key) {
		return settledByAPerson(key).filter((record) -> record.status() == ApprovalStatus.DENIED).isPresent();
	}

	/**
	 * The decision a person has recorded about this principal, if there is one.
	 *
	 * <p>
	 * An invitation may settle somebody nobody has looked at yet. It may not re-settle
	 * somebody who has been decided about — not even to approve them again, because the
	 * roles an approver granted are part of their decision and may be deliberately
	 * narrower than whatever the invitation carries.
	 * @param key the principal being asked about
	 * @return their record when a person decided it, empty when nobody has
	 */
	private Optional<ApprovalRecord> settledByAPerson(ApprovalKey key) {
		return this.approvals.find(key)
			.filter((record) -> record.status() == ApprovalStatus.APPROVED || record.status() == ApprovalStatus.DENIED)
			.filter((record) -> !INVITE_ONLY.equals(record.decidedBy()));
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
