package org.alexmond.uniauth.provider;

/**
 * One selectable way to sign in, as rendered on the chooser page and served by the
 * providers endpoint.
 *
 * @param id stable identifier — the registration id for OAuth2/SAML, the mechanism name
 * for the form-based ones
 * @param type which mechanism backs this entry, and therefore how it is wired
 * @param brand whose service is on the other end; use it for icons and button treatment,
 * not for behaviour
 * @param displayName human-readable label for the button or form heading
 * @param loginUrl where to send the browser to start this flow; {@code null} for
 * form-based providers, which post to the shared form action instead
 * @param oidc whether this provider returns an id_token, and so whether the principal
 * arrives as an {@code OidcUser} carrying claims. Meaningful for
 * {@link AuthProviderType#OAUTH2} only — GitHub is OAuth2 without OpenID Connect, Google
 * is both — and always {@code false} for the other mechanisms.
 */
public record AuthProvider(String id, AuthProviderType type, AuthProviderBrand brand, String displayName,
		String loginUrl, boolean oidc) {

	public boolean isFormBased() {
		return this.type.isFormBased();
	}

}
