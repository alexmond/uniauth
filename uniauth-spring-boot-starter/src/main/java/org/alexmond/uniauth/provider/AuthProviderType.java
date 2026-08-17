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

	/** Accounts declared in configuration, under {@code uniauth.internal.users}. */
	INTERNAL(true),

	/** A directory, authenticated by binding as the user. */
	LDAP(true),

	/**
	 * An OAuth2 or OpenID Connect provider. Whether a given registration is OIDC is a
	 * separate question — see {@link AuthProvider#oidc()}, which is the distinction that
	 * changes what an application receives.
	 */
	OAUTH2(false),

	/** A SAML 2.0 identity provider. */
	SAML(false);

	private final boolean formBased;

	AuthProviderType(boolean formBased) {
		this.formBased = formBased;
	}

	/**
	 * Whether this mechanism uses the shared username/password form.
	 *
	 * <p>
	 * The axis that governs how a mechanism is installed and how the chooser renders it:
	 * form-based mechanisms contribute an {@code AuthenticationProvider} to one form,
	 * while redirect-based ones keep their own entry-point URL and render a link.
	 * @return {@code true} for {@link #INTERNAL} and {@link #LDAP}
	 */
	public boolean isFormBased() {
		return formBased;
	}

}
