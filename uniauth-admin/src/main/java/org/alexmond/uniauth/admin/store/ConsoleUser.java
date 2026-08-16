package org.alexmond.uniauth.admin.store;

import java.util.List;

/**
 * An account as the console sees it.
 *
 * <p>
 * {@code detail} is whatever the store can say about where the account lives — a
 * distinguished name for a directory entry, nothing for a provider account. It is shown
 * rather than interpreted.
 *
 * @param username the account name
 * @param roles roles or group memberships, empty when the store does not report them
 * @param detail store-specific locator, or {@code null}
 */
public record ConsoleUser(String username, List<String> roles, String detail) {

	public ConsoleUser(String username, List<String> roles) {
		this(username, roles, null);
	}

}
