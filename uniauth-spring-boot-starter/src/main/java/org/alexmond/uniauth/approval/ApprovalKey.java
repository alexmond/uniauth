package org.alexmond.uniauth.approval;

import org.alexmond.uniauth.provider.ResolvedMechanism;
import org.springframework.security.core.Authentication;

/**
 * Identifies who an approval decision is about.
 *
 * <p>
 * Keyed on provider <em>and</em> principal, never principal alone. "alice" in the
 * internal store and "alice" at some OIDC provider are different people who happen to
 * share a string, and approving one must not admit the other.
 *
 * @param provider registration id for OAuth2/SAML, or the mechanism name for form-based
 * @param principal the authenticated principal's name
 */
public record ApprovalKey(String provider, String principal) {

	/**
	 * Builds the key for an authenticated principal.
	 *
	 * <p>
	 * The provider half comes from the resolved mechanism rather than the mechanism type,
	 * so two OIDC registrations on one application stay distinct: approving somebody at
	 * one provider must not admit the same name arriving from another.
	 * @param mechanism which provider answered, as resolved from the authentication
	 * @param authentication the authenticated principal
	 * @return the key this principal is approved — or not — under
	 */
	public static ApprovalKey of(ResolvedMechanism mechanism, Authentication authentication) {
		return new ApprovalKey(mechanism.provider(), authentication.getName());
	}

}
