package org.alexmond.uniauth.admin;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.util.List;

/**
 * Creating an account, in whichever place accounts for a given mechanism live.
 *
 * <p>
 * This is an SPI: UniAuth defines the shape and exposes it over the admin API, but has no
 * idea where a given application keeps its users. Publish one bean per store you want
 * administrable and it appears; publish none and the API reports nothing to manage.
 *
 * <p>
 * The three implementations have almost nothing in common underneath — a
 * {@code UserDetailsManager}, an LDAP {@code bind}, and a second in-memory manager
 * belonging to the authorization server — which is rather the point. "Add a user" is one
 * sentence to an administrator and three unrelated operations to the system, and the
 * admin page exists to show exactly that.
 */
public interface UserStoreAdmin {

	/** Which mechanism this store backs. */
	AuthProviderType mechanism();

	/** Human-readable name for the admin page. */
	String displayName();

	/** One line explaining what creating a user here actually does. */
	String description();

	/** Usernames currently in this store. */
	List<String> usernames();

	/**
	 * Adds an account.
	 * @throws IllegalArgumentException if the username is already taken
	 * @throws IllegalStateException if the store cannot be written to
	 */
	void create(String username, String password, List<String> roles);

}
