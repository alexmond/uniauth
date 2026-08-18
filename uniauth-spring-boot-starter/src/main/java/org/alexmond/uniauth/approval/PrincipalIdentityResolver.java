package org.alexmond.uniauth.approval;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
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

	// SAML is optional for a sharper reason than LDAP: OpenSAML is not published to Maven
	// Central, so a transitive dependency on it forces the Shibboleth repository into
	// every consumer's build, whether or not they ever intend to speak SAML.
	private static final boolean SAML_PRESENT = ClassUtils.isPresent(
			"org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal", null);

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
		if (SAML_PRESENT) {
			PrincipalIdentity assertion = Saml.identify(principal, authentication.getName());
			if (assertion != null) {
				return assertion;
			}
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

	private static String join(String given, String surname) {
		if (given == null && surname == null) {
			return null;
		}
		return (given != null && surname != null) ? given + " " + surname : ((given != null) ? given : surname);
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
	 * Kept in its own class so the SAML types are only loaded when
	 * spring-security-saml2-service-provider is present, for the same reason as
	 * {@link Ldap} below.
	 */
	private static final class Saml {

		/**
		 * Reads the assertion's attributes.
		 *
		 * <p>
		 * A SAML principal name is the NameID, which for the persistent format is an
		 * opaque identifier — stable and correct to key on, and useless to an approver.
		 * What makes the decision possible is in the attributes, and only if the identity
		 * provider was configured to release them: an assertion carries whatever the IdP
		 * chose to send and nothing more.
		 *
		 * <p>
		 * Attribute names are the OID URNs from the SAML X.500 attribute profile, with
		 * the friendly names accepted as a fallback because identity providers differ
		 * over which they send. There is no verification claim in that profile — SAML has
		 * no equivalent of {@code email_verified} — so the address is reported with
		 * verification unknown rather than assumed true. Assuming would be the dangerous
		 * direction.
		 */
		static PrincipalIdentity identify(Object principal, String name) {
			return (principal instanceof Saml2AuthenticatedPrincipal saml2) ? fromSaml2(saml2, name) : null;
		}

		private static PrincipalIdentity fromSaml2(Saml2AuthenticatedPrincipal saml2, String name) {
			String displayName = firstAttribute(saml2, "urn:oid:2.16.840.1.113730.3.1.241", "displayName");
			if (displayName == null) {
				String given = firstAttribute(saml2, "urn:oid:2.5.4.42", "givenName");
				String surname = firstAttribute(saml2, "urn:oid:2.5.4.4", "sn");
				displayName = join(given, surname);
			}
			String email = firstAttribute(saml2, "urn:oid:1.2.840.113549.1.9.1", "email", "mail");
			return new PrincipalIdentity(displayName, email, null, name);
		}

		private static String firstAttribute(Saml2AuthenticatedPrincipal principal, String... names) {
			for (String candidate : names) {
				List<Object> values = principal.getAttribute(candidate);
				if (values != null && !values.isEmpty() && StringUtils.hasText(String.valueOf(values.get(0)))) {
					return String.valueOf(values.get(0));
				}
			}
			return null;
		}

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
