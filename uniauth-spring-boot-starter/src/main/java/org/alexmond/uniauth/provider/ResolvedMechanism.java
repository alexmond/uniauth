package org.alexmond.uniauth.provider;

/**
 * Which mechanism authenticated a session, and under which registration.
 *
 * @param type the mechanism that answered
 * @param provider the registration id for OAuth2/SAML, or the mechanism name in lower
 * case for the form-based ones. This is the stable half of an identity: "alice from the
 * internal store" and "alice from Google" are different people and must not share an
 * approval.
 */
public record ResolvedMechanism(AuthProviderType type, String provider) {
}
