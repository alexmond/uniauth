package org.alexmond.uniauth.admin.store;

import java.util.List;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;

import org.alexmond.uniauth.admin.ConsoleProperties;

import org.springframework.ldap.NameAlreadyBoundException;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapNameBuilder;

/**
 * Directory entries, written straight to LDAP.
 *
 * <p>
 * No API sits in front of this one, and none should: the directory <em>is</em> the
 * service, and putting an HTTP shim in front of it would only add a second thing to
 * secure. The bind account is the same one the applications use to resolve groups, which
 * is also why writing needs a real directory rather than the in-process test server —
 * that one has no admin entry to bind as.
 *
 * <p>
 * Roles are read-only here. A directory's groups are entries in their own right, with
 * their own members; offering them as a text field on a user form would suggest they live
 * on the user, which is the opposite of how the group search works.
 */
public class DirectoryUserStore implements UserStore {

	private final ConsoleProperties.Directory config;

	private final LdapTemplate ldap;

	public DirectoryUserStore(ConsoleProperties.Directory config, LdapTemplate ldap) {
		this.config = config;
		this.ldap = ldap;
	}

	@Override
	public String id() {
		return "directory";
	}

	@Override
	public String name() {
		return this.config.getName();
	}

	@Override
	public String mechanism() {
		return "LDAP";
	}

	@Override
	public String location() {
		return this.config.getUrl();
	}

	@Override
	public String description() {
		return "Entries in the LDAP directory. Group membership is administered in the directory "
				+ "itself — groups are entries, not a field on a person.";
	}

	@Override
	public boolean supportsRoles() {
		return false;
	}

	@Override
	public List<ConsoleUser> users() {
		try {
			return this.ldap.search(this.config.getUserBase(), "(objectClass=inetOrgPerson)",
					(AttributesMapper<ConsoleUser>) (attributes) -> {
						String uid = value(attributes, "uid");
						return new ConsoleUser(uid, List.of(), userDn(uid) + "," + this.config.getBaseDn());
					});
		}
		catch (RuntimeException ex) {
			throw new StoreException("The directory is not answering (" + this.config.getUrl() + ")", ex);
		}
	}

	@Override
	public void create(String username, String password, List<String> roles) {
		Attributes attributes = new BasicAttributes();
		BasicAttribute objectClass = new BasicAttribute("objectClass");
		objectClass.add("top");
		objectClass.add("person");
		objectClass.add("organizationalPerson");
		objectClass.add("inetOrgPerson");
		attributes.put(objectClass);
		attributes.put("cn", username);
		// sn is mandatory on person, and there is nothing better to put in it than the
		// name we were given. Guessing a surname out of a username would be worse.
		attributes.put("sn", username);
		attributes.put("uid", username);
		attributes.put("userPassword", password);
		try {
			this.ldap.bind(userDn(username), null, attributes);
		}
		catch (NameAlreadyBoundException ex) {
			throw new StoreException("The directory already has an entry for " + username, ex);
		}
		catch (RuntimeException ex) {
			throw new StoreException("The directory refused the entry: " + ex.getMessage(), ex);
		}
	}

	@Override
	public void setPassword(String username, String password) {
		ModificationItem change = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
				new BasicAttribute("userPassword", password));
		try {
			this.ldap.modifyAttributes(userDn(username), new ModificationItem[] { change });
		}
		catch (NameNotFoundException ex) {
			throw new StoreException("The directory has no entry for " + username, ex);
		}
		catch (RuntimeException ex) {
			throw new StoreException("The directory refused the change: " + ex.getMessage(), ex);
		}
	}

	@Override
	public void setRoles(String username, List<String> roles) {
		throw new StoreException("Group membership is administered in the directory, not here.");
	}

	@Override
	public void delete(String username) {
		String dn = userDn(username);
		try {
			// Look the entry up first, because JNDI specifies unbind as idempotent: it
			// succeeds when the name is not bound. Without this the console cheerfully
			// reports "Removed ghost." having removed nothing, which is worse than an
			// error — it is a false confirmation.
			this.ldap.lookup(dn);
			this.ldap.unbind(dn);
		}
		catch (NameNotFoundException ex) {
			throw new StoreException("The directory has no entry for " + username, ex);
		}
		catch (RuntimeException ex) {
			throw new StoreException("The directory refused the removal: " + ex.getMessage(), ex);
		}
	}

	/**
	 * The entry's DN relative to the base, built rather than concatenated so a username
	 * carrying a comma or an equals sign cannot rewrite the DN it lands in.
	 */
	private String userDn(String username) {
		return LdapNameBuilder.newInstance(this.config.getUserBase())
			.add(this.config.getUserAttribute(), username)
			.build()
			.toString();
	}

	private static String value(Attributes attributes, String id) throws javax.naming.NamingException {
		return (attributes.get(id) != null) ? String.valueOf(attributes.get(id).get()) : null;
	}

}
