package org.alexmond.uniauth.approval;

import jakarta.servlet.http.HttpServletRequest;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.invitation.InvitationRedemption;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.alexmond.uniauth.provider.ResolvedMechanism;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

/**
 * Gates access on approval, after authentication has already succeeded.
 *
 * <p>
 * Authorization is the right layer for this, not authentication. Failing the login
 * instead would report "waiting for approval" as a credentials failure, which is both
 * misleading and a small information leak — it tells an attacker their guess was correct.
 *
 * <p>
 * The first sighting of a principal is recorded here rather than in a success handler.
 * There are four mechanisms and they do not share one, so hooking authentication success
 * would mean four hooks; every request passes through authorization exactly once,
 * whichever way the user got in.
 */
public class ApprovalAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

	/**
	 * Set on the request when access was refused specifically because approval is
	 * outstanding, so the access-denied handler can tell that apart from an ordinary 403.
	 */
	public static final String PENDING_ATTRIBUTE = ApprovalAuthorizationManager.class.getName() + ".PENDING";

	private final ApprovalStore store;

	private final MechanismResolver resolver;

	private final UniAuthProperties properties;

	private final PrincipalIdentityResolver identities = new PrincipalIdentityResolver();

	private final InvitationRedemption redemption;

	/**
	 * Creates the gate without invitations.
	 * @param store where standing is recorded and read
	 * @param resolver works out which provider answered, since approval is per provider
	 * @param properties supplies which mechanisms the gate applies to
	 */
	public ApprovalAuthorizationManager(ApprovalStore store, MechanismResolver resolver, UniAuthProperties properties) {
		this(store, resolver, properties, null);
	}

	/**
	 * Creates the gate.
	 *
	 * <p>
	 * The three-argument constructor is kept rather than widened because this class is
	 * published API: an application that builds its own gate should not break on a
	 * feature it does not use.
	 * @param store where standing is recorded and read
	 * @param resolver works out which provider answered, since approval is per provider
	 * @param properties supplies which mechanisms the gate applies to
	 * @param redemption claims an invitation the session is carrying, or {@code null}
	 * when invitations are switched off — in which case this class behaves exactly as it
	 * did before they existed, {@code invite-only} included, since that setting cannot
	 * mean anything without them
	 */
	public ApprovalAuthorizationManager(ApprovalStore store, MechanismResolver resolver, UniAuthProperties properties,
			InvitationRedemption redemption) {
		this.store = store;
		this.resolver = resolver;
		this.properties = properties;
		this.redemption = redemption;
	}

	@Override
	public AuthorizationDecision authorize(Supplier<? extends Authentication> authentication,
			RequestAuthorizationContext context) {
		Authentication current = authentication.get();
		if (!isAuthenticated(current)) {
			// Refuse and let the entry point redirect to the chooser, exactly as
			// .authenticated() would have.
			return new AuthorizationDecision(false);
		}
		ResolvedMechanism mechanism = this.resolver.resolve(current);
		ApprovalKey key = ApprovalKey.of(mechanism, current);
		PrincipalIdentity identity = this.identities.resolve(current);
		// Ahead of the require-for check on purpose. An invitation is not a gate: it says
		// who this login belongs to, and the application wants that link whether or not
		// the mechanism they used is gated. require-for excludes INTERNAL by default, so
		// behind that check an invitation completed with an internal login would claim
		// nothing, publish nothing and record no usedBy — while letting the person in, so
		// nothing would look wrong to them or to whoever invited them.
		//
		// Also ahead of the status read, because claiming is what changes the status.
		// Runs
		// whatever the current standing: a session that survived the round trip arrives
		// UNKNOWN, one lost to a restart arrives PENDING and reopens the URL, and
		// somebody
		// already signed in accepts on the invitation page. All three have to work.
		boolean admitted = this.redemption != null
				&& this.redemption.admit(context.getRequest(), key, identity, mechanism.type());
		if (admitted) {
			grantApprovedRoles(key, current);
			return new AuthorizationDecision(true);
		}
		if (!this.properties.getApproval().getRequireFor().contains(mechanism.type())) {
			return new AuthorizationDecision(true);
		}
		ApprovalStatus status = this.store.statusOf(key);
		if (status == ApprovalStatus.UNKNOWN) {
			// Resolved here, at the one moment the principal is present. The queue is
			// read later, by someone else, when this session may be long gone.
			this.store.recordPending(key, identity, mechanism.type());
			status = inviteOnly() ? refuse(key) : ApprovalStatus.PENDING;
		}
		if (status == ApprovalStatus.APPROVED) {
			return new AuthorizationDecision(true);
		}
		markPending(context.getRequest(), status);
		return new AuthorizationDecision(false);
	}

	private static boolean isAuthenticated(Authentication authentication) {
		return authentication != null && authentication.isAuthenticated()
				&& !(authentication instanceof AnonymousAuthenticationToken);
	}

	/**
	 * A denial is flagged only while it is still reversible. Someone already refused
	 * should see a plain 403 rather than a page inviting them to wait.
	 */
	private static void markPending(HttpServletRequest request, ApprovalStatus status) {
		if (request != null && status == ApprovalStatus.PENDING) {
			request.setAttribute(PENDING_ATTRIBUTE, Boolean.TRUE);
		}
	}

	/**
	 * Whether an uninvited principal should be refused outright.
	 *
	 * <p>
	 * Only meaningful with invitations switched on: without them nobody can be invited,
	 * so honouring the flag would lock out every user of an application that set it by
	 * accident.
	 */
	private boolean inviteOnly() {
		return this.redemption != null && this.properties.getApproval().getInvitations().isInviteOnly();
	}

	/**
	 * Records a refusal for somebody who will not be admitted.
	 *
	 * <p>
	 * Only ever applied to a principal seen for the first time. Somebody already waiting
	 * was recorded under an earlier configuration, and flipping them to {@code DENIED}
	 * would turn a queue a human was about to read into a silent refusal.
	 */
	/**
	 * Puts the roles the admission just granted onto this request's authentication.
	 *
	 * <p>
	 * {@link ApprovalAuthoritiesFilter} cannot do it for an invitation. It runs before
	 * {@code AuthorizationFilter} — it has to, or an approver's roles would arrive after
	 * the decision that needed them — but roles an invitation grants are created
	 * <em>by</em> this decision, so by then the filter has already run. Without this the
	 * invited person lands on their first {@code hasRole}-gated page, gets 403, and finds
	 * it works on refresh.
	 */
	private void grantApprovedRoles(ApprovalKey key, Authentication current) {
		Authentication granted = ApprovalAuthoritiesFilter.granting(current,
				this.store.find(key)
					.filter((record) -> record.status() == ApprovalStatus.APPROVED)
					.map(ApprovalRecord::roles)
					.orElse(java.util.List.of()));
		if (granted != null) {
			SecurityContextHolder.getContext().setAuthentication(granted);
		}
	}

	private ApprovalStatus refuse(ApprovalKey key) {
		this.store.decide(key, ApprovalStatus.DENIED, InvitationRedemption.INVITE_ONLY, java.util.List.of());
		return ApprovalStatus.DENIED;
	}

}
