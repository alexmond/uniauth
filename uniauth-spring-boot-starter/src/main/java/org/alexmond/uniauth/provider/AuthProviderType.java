package org.alexmond.uniauth.provider;

/**
 * The authentication mechanisms UniAuth can expose.
 *
 * <p>
 * {@link #INTERNAL} and {@link #LDAP} are <em>form-based</em>: they share the single
 * username/password form on the login page and are resolved by the
 * {@code AuthenticationProvider} chain. {@link #OAUTH2} and {@link #SAML} are
 * <em>redirect-based</em>: each registration renders its own button.
 */
public enum AuthProviderType {

	INTERNAL(true), LDAP(true), OAUTH2(false), SAML(false);

	private final boolean formBased;

	AuthProviderType(boolean formBased) {
		this.formBased = formBased;
	}

	public boolean isFormBased() {
		return formBased;
	}

}
