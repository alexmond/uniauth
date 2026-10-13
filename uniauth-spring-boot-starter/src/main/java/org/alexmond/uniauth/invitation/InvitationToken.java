package org.alexmond.uniauth.invitation;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.util.Assert;

/**
 * The invitation's credential: whoever holds it can claim the record it names.
 *
 * <p>
 * Opaque, URL-safe, and generated from {@link SecureRandom} with 128 bits of entropy. It
 * is never derived from the {@code subjectRef} — a token a person could guess from
 * somebody's name would not be a credential at all.
 *
 * <p>
 * Deliberately not a signed self-contained token. One-use and revocation both require a
 * store lookup, so statelessness would buy nothing, while a signed token would have to
 * ride the provider round trip as OAuth2 {@code state} or SAML {@code RelayState} — two
 * mechanisms, two implementations, which is precisely the split the single chain exists
 * to avoid.
 *
 * @param value the opaque, URL-safe token text
 */
public record InvitationToken(String value) {

	private static final SecureRandom RANDOM = new SecureRandom();

	private static final int ENTROPY_BYTES = 16;

	public InvitationToken {
		Assert.hasText(value, "An invitation token must have text");
	}

	/**
	 * Mints a fresh token.
	 * @return a token with 128 bits of entropy, encoded URL-safely and without padding so
	 * it needs no escaping in a path
	 */
	public static InvitationToken generate() {
		byte[] bytes = new byte[ENTROPY_BYTES];
		RANDOM.nextBytes(bytes);
		return new InvitationToken(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
	}

	/**
	 * Wraps token text that arrived from outside — a URL, or a store.
	 * @param value the token text, which is not validated beyond being non-blank: an
	 * unrecognised token is a lookup miss, not an error
	 * @return the token
	 */
	public static InvitationToken of(String value) {
		return new InvitationToken(value);
	}

	/**
	 * Withholds the value.
	 *
	 * <p>
	 * This is a bearer credential, and the one place such a thing reliably leaks is a log
	 * line that interpolated an object someone assumed was harmless.
	 * @return a constant placeholder
	 */
	@Override
	public String toString() {
		return "InvitationToken[redacted]";
	}

}
