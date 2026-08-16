package org.alexmond.uniauth.approval;

/**
 * Who is waiting, in terms a person can act on.
 *
 * <p>
 * Separate from {@link ApprovalKey} on purpose, and it must stay that way. The key is
 * {@code (provider, subject)} because a subject is stable and never reassigned; an email
 * address can change hands, and keying on one would eventually admit the wrong person.
 * But a subject is also unreadable — Google's is a twenty-one digit number — so approving
 * on the key alone means deciding about a stranger. This is what makes the decision
 * possible without making it unsafe.
 *
 * <p>
 * Captured at first sighting rather than read live: the queue has to render for a
 * principal who is no longer signed in, and the details that mattered are the ones
 * presented when they turned up.
 *
 * @param displayName a human name, or {@code null} when the provider gives none
 * @param email the address claimed, or {@code null}
 * @param emailVerified whether the provider says it verified that address — {@code null}
 * when it does not say. An unverified address is a claim, not evidence, and an approver
 * deciding on one is trusting whoever typed it rather than the provider
 * @param subject the stable identifier the key is built from, shown so an approver can
 * see exactly what is being admitted
 */
public record PrincipalIdentity(String displayName, String email, Boolean emailVerified, String subject) {

	/** For mechanisms that carry nothing beyond a name. */
	public static PrincipalIdentity ofName(String name) {
		return new PrincipalIdentity(null, null, null, name);
	}

}
