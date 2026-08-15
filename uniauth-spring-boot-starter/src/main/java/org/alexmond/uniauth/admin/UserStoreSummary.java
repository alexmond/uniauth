package org.alexmond.uniauth.admin;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.util.List;

/**
 * One administrable store, as the management API reports it.
 *
 * @param mechanism which mechanism this store backs
 * @param displayName human-readable name
 * @param description what creating a user here actually does — the stores differ enough
 * that a console showing only names would mislead
 * @param usernames who is in it
 */
public record UserStoreSummary(AuthProviderType mechanism, String displayName, String description,
		List<String> usernames) {

	static UserStoreSummary of(UserStoreAdmin store) {
		return new UserStoreSummary(store.mechanism(), store.displayName(), store.description(), store.usernames());
	}

}
