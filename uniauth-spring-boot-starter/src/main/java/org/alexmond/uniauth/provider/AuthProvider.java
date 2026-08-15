package org.alexmond.uniauth.provider;

/**
 * One selectable way to sign in, as rendered on the chooser page and served by the
 * providers endpoint.
 *
 * @param id stable identifier — the registration id for OAuth2/SAML, the mechanism name
 * for the form-based ones
 * @param type which mechanism backs this entry
 * @param displayName human-readable label for the button or form heading
 * @param loginUrl where to send the browser to start this flow; {@code null} for
 * form-based providers, which post to the shared form action instead
 */
public record AuthProvider(String id, AuthProviderType type, String displayName, String loginUrl) {

	public boolean isFormBased() {
		return type.isFormBased();
	}
}
