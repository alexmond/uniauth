package org.alexmond.uniauth.examples.admin;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Accounts in the starter's internal store.
 *
 * <p>
 * The starter's default {@code UserDetailsService} is an
 * {@code InMemoryUserDetailsManager}, which is also a {@link UserDetailsManager} — so
 * creating a user is a one-liner. It is also why these accounts vanish on restart, and
 * why the ones declared under {@code uniauth.internal.users} come back and these do not.
 */
@Component
public class InternalUserStoreAdmin implements UserStoreAdmin {

	private final UserDetailsManager users;

	private final PasswordEncoder passwordEncoder;

	/** Seeded from configuration, then extended by whatever the admin page adds. */
	private final List<String> usernames = new CopyOnWriteArrayList<>();

	public InternalUserStoreAdmin(UserDetailsManager users, PasswordEncoder passwordEncoder,
			UniAuthProperties properties) {
		this.users = users;
		this.passwordEncoder = passwordEncoder;
		properties.getInternal().getUsers().forEach((configured) -> this.usernames.add(configured.getUsername()));
	}

	@Override
	public AuthProviderType mechanism() {
		return AuthProviderType.INTERNAL;
	}

	@Override
	public String displayName() {
		return "Internal store";
	}

	@Override
	public String description() {
		return "In-memory accounts held by the application itself. Lost on restart — the ones in "
				+ "application.yaml come back, these do not.";
	}

	@Override
	public List<String> usernames() {
		return List.copyOf(this.usernames);
	}

	@Override
	public void create(String username, String password, List<String> roles) {
		if (this.users.userExists(username)) {
			throw new IllegalArgumentException("There is already an internal account called " + username);
		}
		this.users.createUser(User.withUsername(username)
			.password(this.passwordEncoder.encode(password))
			.roles(roles.toArray(String[]::new))
			.build());
		this.usernames.add(username);
	}

}
