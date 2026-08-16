package org.alexmond.uniauth.authserver.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The accounts this provider knows about.
 *
 * <p>
 * In memory, which is honest for a demo and stated everywhere it matters: restart the
 * provider and everything created through the admin API is gone. A real deployment swaps
 * this for a database-backed {@code UserDetailsManager} — the rest of the service does
 * not care which it is.
 */
@Component
public final class AccountStore {

	private final InMemoryUserDetailsManager delegate = new InMemoryUserDetailsManager();

	/**
	 * {@code InMemoryUserDetailsManager} cannot list its users; this mirror is the
	 * listing.
	 */
	private final List<String> usernames = new CopyOnWriteArrayList<>();

	/**
	 * The profile claims, which {@code UserDetails} has nowhere to put.
	 *
	 * <p>
	 * Kept beside the credentials rather than folded into them: a name and an address are
	 * things the provider asserts <em>about</em> an account, not things it authenticates
	 * with, and the distinction is what lets email_verified mean anything.
	 */
	private final Map<String, Profile> profiles = new ConcurrentHashMap<>();

	private final PasswordEncoder passwordEncoder;

	public AccountStore(PasswordEncoder passwordEncoder, AuthServerProperties properties) {
		this.passwordEncoder = passwordEncoder;
		properties.getUsers()
			.forEach((seed) -> create(seed.getUsername(), seed.getPassword(), seed.getRoles(),
					new Profile(seed.getName(), seed.getEmail(), seed.isEmailVerified())));
	}

	/** The manager the login chain authenticates against. */
	public UserDetailsManager manager() {
		return this.delegate;
	}

	public List<Account> accounts() {
		return this.usernames.stream().map((name) -> new Account(name, rolesOf(name), profileOf(name))).toList();
	}

	/** The claims this provider asserts about an account, never {@code null}. */
	public Profile profileOf(String username) {
		return this.profiles.getOrDefault(username, Profile.EMPTY);
	}

	public void create(String username, String rawPassword, List<String> roles) {
		create(username, rawPassword, roles, Profile.EMPTY);
	}

	public void create(String username, String rawPassword, List<String> roles, Profile profile) {
		if (this.delegate.userExists(username)) {
			throw new IllegalArgumentException("There is already an account called " + username);
		}
		this.delegate.createUser(User.withUsername(username)
			.password(this.passwordEncoder.encode(rawPassword))
			.roles(roles.toArray(String[]::new))
			.build());
		this.usernames.add(username);
		this.profiles.put(username, (profile != null) ? profile : Profile.EMPTY);
	}

	/** Replaces the asserted claims. Absent fields are cleared, not merged. */
	public void updateProfile(String username, Profile profile) {
		require(username);
		this.profiles.put(username, (profile != null) ? profile : Profile.EMPTY);
	}

	public void updatePassword(String username, String rawPassword) {
		// Rebuilt from the existing account so a password reset does not drop the roles.
		UserDetails existing = require(username);
		this.delegate
			.updateUser(User.withUserDetails(existing).password(this.passwordEncoder.encode(rawPassword)).build());
	}

	public void updateRoles(String username, List<String> roles) {
		UserDetails existing = require(username);
		this.delegate.updateUser(User.withUsername(username)
			.password(existing.getPassword())
			.roles(roles.toArray(String[]::new))
			.build());
	}

	public void delete(String username) {
		require(username);
		this.delegate.deleteUser(username);
		this.usernames.remove(username);
		this.profiles.remove(username);
	}

	private UserDetails require(String username) {
		try {
			return this.delegate.loadUserByUsername(username);
		}
		catch (UsernameNotFoundException ex) {
			throw new IllegalArgumentException("There is no account called " + username, ex);
		}
	}

	private List<String> rolesOf(String username) {
		try {
			return this.delegate.loadUserByUsername(username)
				.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.toList();
		}
		catch (UsernameNotFoundException ex) {
			return List.of();
		}
	}

	/**
	 * One account, as an administrator sees it. No password: it goes in one direction
	 * only.
	 */
	public record Account(String username, List<String> roles, Profile profile) {
	}

	/**
	 * What the provider asserts about an account.
	 *
	 * @param name a human name, or {@code null}
	 * @param email an address, or {@code null}
	 * @param emailVerified whether this provider checked that address. False is the
	 * honest default — an unchecked address is a claim, and a relying party that treats
	 * it as identity is trusting whoever typed it rather than this provider
	 */
	public record Profile(String name, String email, boolean emailVerified) {

		public static final Profile EMPTY = new Profile(null, null, false);

	}

}
