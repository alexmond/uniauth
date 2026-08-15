package org.alexmond.uniauth.examples.oauth;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The accounts that exist at the local authorization server.
 *
 * <p>
 * These are a genuinely separate population from {@code uniauth.internal.users}: signing
 * in through the OAuth button proves you to the <em>provider</em>, which then vouches for
 * you to the application. Sharing one store would have made the OAuth path
 * indistinguishable from the internal one, and the demo pointless.
 *
 * <p>
 * The manager is wrapped rather than published as a bean on purpose. A second
 * {@code UserDetailsService} in the context would satisfy the starter's
 * {@code @ConditionalOnMissingBean(UserDetailsService.class)} and silently switch the
 * internal store off, so this type is the only thing the container sees.
 */
@Component
public final class OAuthUserStore {

	private final InMemoryUserDetailsManager delegate = new InMemoryUserDetailsManager();

	/**
	 * {@code InMemoryUserDetailsManager} can answer "does this user exist" but cannot
	 * list its users, and the admin UI has to show them. This mirror is the listing.
	 */
	private final List<String> usernames = new CopyOnWriteArrayList<>();

	private final PasswordEncoder passwordEncoder;

	public OAuthUserStore(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
		// Seeded so the OAuth button works on a fresh start, the same way the internal
		// store and the directory ship with accounts.
		create("olivia", "oauth-pass", List.of("USER"));
	}

	/** The manager the authorization server's login chain authenticates against. */
	public UserDetailsManager manager() {
		return this.delegate;
	}

	public void create(String username, String rawPassword, List<String> roles) {
		UserDetails user = User.withUsername(username)
			.password(this.passwordEncoder.encode(rawPassword))
			.roles(roles.toArray(String[]::new))
			.build();
		this.delegate.createUser(user);
		this.usernames.add(username);
	}

	public boolean exists(String username) {
		return this.delegate.userExists(username);
	}

	public List<String> usernames() {
		return List.copyOf(this.usernames);
	}

}
