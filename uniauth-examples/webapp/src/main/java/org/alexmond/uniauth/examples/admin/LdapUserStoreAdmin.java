package org.alexmond.uniauth.examples.admin;

import org.alexmond.uniauth.provider.AuthProviderType;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.stereotype.Component;

import javax.naming.Name;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Accounts in the directory.
 *
 * <p>
 * The one store here that is not a Java collection: creating a user means binding a real
 * {@code inetOrgPerson} entry under {@code ou=people}. The embedded UnboundID server the
 * demo runs accepts writes, so the same code would work against a real directory — though
 * a real one would rarely let an application create entries.
 *
 * <p>
 * Note what is <em>not</em> set: group membership. The demo's authorities come from
 * {@code ou=groups}, so a user created here signs in successfully with no roles at all
 * until someone adds them to a group. That is a faithful reflection of how directories
 * work, not an oversight.
 */
@Component
public class LdapUserStoreAdmin implements UserStoreAdmin {

	private final LdapTemplate ldapTemplate;

	public LdapUserStoreAdmin(LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	@Override
	public AuthProviderType mechanism() {
		return AuthProviderType.LDAP;
	}

	@Override
	public String displayName() {
		return "Directory";
	}

	@Override
	public String description() {
		return "A real inetOrgPerson entry under ou=people. Roles come from group membership, "
				+ "which this form does not set — a new directory user signs in with no authorities.";
	}

	@Override
	public List<String> usernames() {
		try {
			return this.ldapTemplate.search("ou=people", "(objectclass=inetOrgPerson)",
					(AttributesMapper<String>) (attributes) -> value(attributes, "uid"));
		}
		catch (RuntimeException ex) {
			// The directory being unreachable should degrade the page, not break it.
			return List.of();
		}
	}

	@Override
	public void create(String username, String password, List<String> roles) {
		if (usernames().contains(username)) {
			throw new IllegalArgumentException("There is already a directory entry for " + username);
		}
		Name dn = LdapNameBuilder.newInstance().add("ou", "people").add("uid", username).build();

		Attributes attributes = new BasicAttributes();
		Attribute objectClass = new BasicAttribute("objectclass");
		objectClass.add("top");
		objectClass.add("person");
		objectClass.add("organizationalPerson");
		objectClass.add("inetOrgPerson");
		attributes.put(objectClass);
		attributes.put("uid", username);
		attributes.put("cn", username);
		// inetOrgPerson requires sn; without it the bind is rejected by schema.
		attributes.put("sn", username);
		attributes.put("userPassword", password.getBytes(StandardCharsets.UTF_8));

		try {
			this.ldapTemplate.bind(dn, null, attributes);
		}
		catch (RuntimeException ex) {
			throw new IllegalStateException("The directory refused the entry: " + ex.getMessage(), ex);
		}
	}

	private static String value(Attributes attributes, String id) {
		try {
			Attribute attribute = attributes.get(id);
			return (attribute != null) ? String.valueOf(attribute.get()) : "";
		}
		catch (Exception ex) {
			return "";
		}
	}

}
