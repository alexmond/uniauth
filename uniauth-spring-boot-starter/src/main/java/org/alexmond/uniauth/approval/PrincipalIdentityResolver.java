package org.alexmond.uniauth.approval;

import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

/**
 * Works out who a principal is, for someone about to decide whether to admit them.
 *
 * <p>
 * Reads the concrete {@code Authentication} types, because nothing records this directly.
 * That is the same technique the sample's session page uses, promoted here now that the
 * approval gate depends on it — the queue was rendering Google's subject claim, a
 * twenty-one digit number, as the only thing an approver knew about the person they were
 * admitting.
 *
 * <p>
 * Deliberately gives back what the provider actually said rather than a best guess. An
 * absent email is shown as absent; an unverified one is shown as unverified. Filling
 * either in would make the queue look more informative than it is, which is the opposite
 * of useful when the whole page exists to support a judgement.
 */
public class PrincipalIdentityResolver {

	// null asks ClassUtils for the default class loader, which is also what the rest of
	// the starter's optional-dependency checks use.
	private static final boolean LDAP_PRESENT = ClassUtils
		.isPresent("org.springframework.security.ldap.userdetails.LdapUserDetails", null);

	/**
	 * Works out who a principal is, for somebody about to decide whether to admit them.
	 * @param authentication the authenticated principal, or {@code null}
	 * @return what the provider actually said — an absent email is reported as absent and
	 * an unverified one as unverified, because filling either in would make a queue look
	 * more informative than it is
	 */
	public PrincipalIdentity resolve(Authentication authentication) {
		if (authentication == null) {
			return PrincipalIdentity.ofName(null);
		}
		Object principal = authentication.getPrincipal();
		if (principal instanceof OidcUser oidc) {
			return fromOidc(oidc, authentication.getName());
		}
		if (principal instanceof OAuth2User oauth2) {
			return fromOauth2(oauth2, authentication.getName());
		}
		if (LDAP_PRESENT) {
			PrincipalIdentity directory = Ldap.identify(principal, authentication.getName());
			if (directory != null) {
				return directory;
			}
		}
		return PrincipalIdentity.ofName(authentication.getName());
	}

	private static PrincipalIdentity fromOidc(OidcUser oidc, String name) {
		// Standard OIDC claims, so this works for any conforming provider rather than
		// only the ones this project has been pointed at.
		return new PrincipalIdentity(text(oidc.getFullName()), text(oidc.getEmail()), oidc.getEmailVerified(), name);
	}

	private static PrincipalIdentity fromOauth2(OAuth2User oauth2, String name) {
		Map<String, Object> attributes = oauth2.getAttributes();
		// GitHub calls it "login" and may not give an email at all until asked for one —
		// which is what GithubEmailOAuth2UserService exists to do.
		String displayName = firstOf(attributes, "name", "login", "preferred_username");
		Boolean verified = (attributes.get("email_verified") instanceof Boolean flag) ? flag : null;
		return new PrincipalIdentity(displayName, firstOf(attributes, "email"), verified, name);
	}

	private static String firstOf(Map<String, Object> attributes, String... keys) {
		for (String key : keys) {
			Object value = attributes.get(key);
			if (value != null && StringUtils.hasText(value.toString())) {
				return value.toString();
			}
		}
		return null;
	}

	private static String text(String value) {
		return StringUtils.hasText(value) ? value : null;
	}

	/**
	 * Kept in its own class so the LDAP types are only loaded when spring-ldap is
	 * actually present. An {@code instanceof} against an absent type in the enclosing
	 * method can fail verification before the guard ever runs.
	 */
	private static final class Ldap {

		static PrincipalIdentity identify(Object principal, String name) {
			if (principal instanceof org.springframework.security.ldap.userdetails.LdapUserDetails ldap) {
				// The DN is the directory's own answer to "which entry is this", and it
				// is readable, so it serves as both name and locator.
				return new PrincipalIdentity(ldap.getDn(), null, null, name);
			}
			return null;
		}

	}

}
