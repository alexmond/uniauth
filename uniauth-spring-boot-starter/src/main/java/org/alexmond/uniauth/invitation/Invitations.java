package org.alexmond.uniauth.invitation;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * Carries an invitation across the provider round trip, in the session.
 *
 * <p>
 * The session is the only place it can go. The token has to survive a redirect out to
 * Google or an identity provider and back, and the alternatives are per-mechanism: OAuth2
 * has {@code state}, SAML has {@code RelayState}, form login has neither. Using them
 * would mean three implementations of one idea, which is the split the single chain
 * exists to avoid.
 *
 * <p>
 * The cost is that a session lost mid-login loses the token. That is a real case —
 * sessions are in memory, which is why the deployments are {@code Recreate} — and the
 * recovery is the invitation URL itself: it is still unclaimed, so reopening it claims it
 * directly, without a second sign-in.
 */
public final class Invitations {

	/**
	 * Where the pending token sits on the session, as the token's text.
	 *
	 * <p>
	 * Text rather than the {@link InvitationToken} record, because a session attribute
	 * has to survive whatever the deployment stores sessions in — and the common stores
	 * default to JDK serialization.
	 */
	public static final String SESSION_ATTRIBUTE = Invitations.class.getName() + ".TOKEN";

	private Invitations() {
	}

	/**
	 * Remembers a validated token for the rest of this session.
	 * @param request the request whose session should carry it
	 * @param token the token to carry
	 */
	public static void stash(HttpServletRequest request, InvitationToken token) {
		// The token's text, not the record. A session attribute has to survive whatever
		// the deployment stores sessions in, and spring-session-data-redis,
		// spring-session-jdbc, Tomcat persistence and Tomcat replication all default to
		// JDK serialization — which would throw on a record that does not declare itself
		// Serializable, on the POST that accepts the invitation. A String has no such
		// contract to get wrong, and none to keep stable across versions either.
		request.getSession(true).setAttribute(SESSION_ATTRIBUTE, token.value());
	}

	/**
	 * The token this session is carrying, if any.
	 * @param request the request to read
	 * @return the token, or {@code null} when there is none. Deliberately does not create
	 * a session: this is called on every authorized request, and creating one for each
	 * would turn a stateless API call into a stateful one
	 */
	public static InvitationToken pending(HttpServletRequest request) {
		if (request == null) {
			return null;
		}
		HttpSession session = request.getSession(false);
		Object stashed = (session != null) ? session.getAttribute(SESSION_ATTRIBUTE) : null;
		// Anything other than token text reads as no invitation. A rolling upgrade can
		// hand this a session written by an earlier version, and throwing on every
		// request would be a worse answer than sending the person through the ordinary
		// gate.
		return (stashed instanceof String value) ? InvitationToken.of(value) : null;
	}

	/**
	 * Forgets the token.
	 *
	 * <p>
	 * Called both when it is claimed and when it turns out to be unusable — leaving a
	 * dead token behind would have the gate re-attempt it on every request for the life
	 * of the session.
	 * @param request the request whose session should forget it
	 */
	public static void clear(HttpServletRequest request) {
		if (request == null) {
			return;
		}
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.removeAttribute(SESSION_ATTRIBUTE);
		}
	}

}
