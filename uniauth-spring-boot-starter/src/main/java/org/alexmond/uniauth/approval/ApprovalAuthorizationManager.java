package org.alexmond.uniauth.approval;

import jakarta.servlet.http.HttpServletRequest;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.alexmond.uniauth.provider.ResolvedMechanism;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
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

	public ApprovalAuthorizationManager(ApprovalStore store, MechanismResolver resolver, UniAuthProperties properties) {
		this.store = store;
		this.resolver = resolver;
		this.properties = properties;
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
		if (!this.properties.getApproval().getRequireFor().contains(mechanism.type())) {
			return new AuthorizationDecision(true);
		}
		ApprovalKey key = ApprovalKey.of(mechanism, current);
		ApprovalStatus status = this.store.statusOf(key);
		if (status == ApprovalStatus.UNKNOWN) {
			this.store.recordPending(key, mechanism.type());
			status = ApprovalStatus.PENDING;
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

}
