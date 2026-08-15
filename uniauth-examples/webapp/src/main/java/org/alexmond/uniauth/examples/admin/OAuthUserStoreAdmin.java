package org.alexmond.uniauth.examples.admin;

import org.alexmond.uniauth.examples.oauth.OAuthUserStore;
import org.alexmond.uniauth.admin.UserStoreAdmin;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Accounts at the local authorization server.
 *
 * <p>
 * Worth being precise about what this creates: not a user of the application, but a user
 * of the <em>provider</em>. They can then sign in through the OAuth button, at which
 * point the provider vouches for them and the application decides separately whether to
 * let them in — which, with the approval gate on for OAUTH2, means waiting in the queue.
 */
@Component
public class OAuthUserStoreAdmin implements UserStoreAdmin {

	private final OAuthUserStore store;

	public OAuthUserStoreAdmin(OAuthUserStore store) {
		this.store = store;
	}

	@Override
	public AuthProviderType mechanism() {
		return AuthProviderType.OAUTH2;
	}

	@Override
	public String displayName() {
		return "Local OAuth provider";
	}

	@Override
	public String description() {
		return "An account at the identity provider, not at this application. They sign in through "
				+ "the OAuth button, and the approval gate still applies afterwards.";
	}

	@Override
	public List<String> usernames() {
		return this.store.usernames();
	}

	@Override
	public void create(String username, String password, List<String> roles) {
		if (this.store.exists(username)) {
			throw new IllegalArgumentException("There is already a provider account called " + username);
		}
		this.store.create(username, password, roles);
	}

}
