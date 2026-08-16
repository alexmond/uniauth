package org.alexmond.uniauth.admin.store;

import java.util.List;

/**
 * A population of accounts this console can administer.
 *
 * <p>
 * There are exactly two, and the difference between them is the whole reason this console
 * is hard: the provider's accounts are reached over HTTP, the directory's over LDAP. What
 * they have in common is small enough to fit here, and pushing any more behind this
 * interface would mean inventing a lowest common denominator neither side actually has.
 *
 * <p>
 * Note what is <em>not</em> here: a UniAuth application's internal store. It used to be,
 * over an admin API the starter published. That API is gone — an authentication library
 * has no business exposing a write endpoint — and with it the pretence that accounts
 * living in an application's memory were administrable in any meaningful sense. They
 * vanished on restart.
 */
public interface UserStore {

	/** Short identifier used in URLs. */
	String id();

	/** Name shown in the console. */
	String name();

	/**
	 * The mechanism these accounts sign in with — {@code OIDC}, {@code LDAP}.
	 *
	 * <p>
	 * Named on the card because a service name does not say what it holds: "UniAuth
	 * provider" reads as a piece of infrastructure rather than as the place OAuth users
	 * live, and the question it prompts is where the OIDC store went. The application's
	 * own provider panel labels every entry with its mechanism for the same reason.
	 */
	String mechanism();

	/** Where the accounts actually live, shown so nobody has to guess. */
	String location();

	/** One line on what this store is for. */
	String description();

	/**
	 * Whether roles can be set here.
	 *
	 * <p>
	 * The directory says no: its group memberships are entries in their own right, and
	 * editing them through a user form would misrepresent what a group is.
	 */
	boolean supportsRoles();

	List<ConsoleUser> users();

	void create(String username, String password, List<String> roles);

	void setPassword(String username, String password);

	void setRoles(String username, List<String> roles);

	void delete(String username);

}
