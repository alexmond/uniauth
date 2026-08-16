package org.alexmond.uniauth.examples.web;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import org.alexmond.uniauth.approval.ApprovalRecord;
import org.alexmond.uniauth.approval.PrincipalIdentity;

/**
 * One row of the approval queue, shaped for reading.
 *
 * <p>
 * The row used to be the approval key and a timestamp. For a Google login the key is a
 * subject claim — {@code 106681014797278784721} — so the page asked an administrator to
 * admit a number. Everything below exists to make the decision possible: a name and an
 * address to recognise, whether the provider actually verified that address, and the
 * subject still shown because it is what is really being admitted.
 *
 * @param principal the stable identifier, which is what approval is keyed on
 * @param displayName a human name, or {@code null} when the provider gives none
 * @param email the address claimed, or {@code null}
 * @param emailStatus "verified", "UNVERIFIED", or {@code null} when the provider is
 * silent
 * @param provider the registration that vouched for them
 * @param mechanism which mechanism that was
 * @param firstSeen when they first turned up, to the minute
 */
public record PendingView(String principal, String displayName, String email, String emailStatus, String provider,
		String mechanism, String firstSeen) {

	private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'")
		.withZone(ZoneOffset.UTC);

	public static PendingView of(ApprovalRecord record) {
		PrincipalIdentity identity = record.identity();
		return new PendingView(record.key().principal(), (identity != null) ? identity.displayName() : null,
				(identity != null) ? identity.email() : null, emailStatus(identity), record.key().provider(),
				record.mechanism().name(), STAMP.format(record.firstSeen()));
	}

	/**
	 * Silence and "unverified" are different answers and the page says which.
	 *
	 * <p>
	 * An unverified address is a claim the user typed, not something the provider stands
	 * behind — approving on one is trusting the wrong party, and it is the difference
	 * between admitting a colleague and admitting whoever asserted their address.
	 */
	private static String emailStatus(PrincipalIdentity identity) {
		if (identity == null || identity.email() == null || identity.emailVerified() == null) {
			return null;
		}
		return identity.emailVerified() ? "verified" : "UNVERIFIED";
	}

}
