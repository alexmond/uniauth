package org.alexmond.uniauth.admin.store;

/**
 * A store refused an operation, or could not be reached.
 *
 * <p>
 * Carries a message meant for an administrator's screen. The distinction worth preserving
 * is "the far side said no" versus "the far side is not answering" — both are routine
 * here, and a stack trace tells an operator neither.
 */
public class StoreException extends RuntimeException {

	public StoreException(String message) {
		super(message);
	}

	public StoreException(String message, Throwable cause) {
		super(message, cause);
	}

}
