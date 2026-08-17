package org.alexmond.uniauth.provider;

import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

/**
 * Works out which of the four mechanisms authenticated the current session.
 *
 * <p>
 * Nothing on {@code Authentication} records this, so the answer is read off the concrete
 * types Spring Security leaves behind. The redirect-based mechanisms each have their own
 * token class and carry a registration id. The two form-based ones both produce a
 * {@code UsernamePasswordAuthenticationToken} and are told apart by their principal: only
 * {@code LdapAuthenticationProvider} returns an {@link LdapUserDetails}.
 *
 * <p>
 * This started in the sample app, kept out of the library until something depended on it.
 * The approval flow is that dependency: an approval is granted to a principal <em>from a
 * particular provider</em>, so the decision cannot be made without this.
 */
public class MechanismResolver {

	/**
	 * Works out which provider vouched for a principal.
	 *
	 * <p>
	 * Reads the concrete {@code Authentication} types, because nothing records this
	 * directly: OAuth2 and SAML carry their own token classes, while internal and LDAP
	 * both produce a {@code UsernamePasswordAuthenticationToken} and are told apart by
	 * whether the principal is an {@code LdapUserDetails}.
	 * @param authentication the authenticated principal
	 * @return the mechanism and the provider within it, never {@code null}
	 */
	public ResolvedMechanism resolve(Authentication authentication) {
		if (authentication instanceof OAuth2AuthenticationToken oauth2) {
			return new ResolvedMechanism(AuthProviderType.OAUTH2, oauth2.getAuthorizedClientRegistrationId());
		}
		if (authentication instanceof Saml2Authentication saml2) {
			String registrationId = null;
			if (saml2.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal) {
				registrationId = principal.getRelyingPartyRegistrationId();
			}
			return new ResolvedMechanism(AuthProviderType.SAML, (registrationId != null) ? registrationId : "saml");
		}
		if (authentication != null && authentication.getPrincipal() instanceof LdapUserDetails) {
			return new ResolvedMechanism(AuthProviderType.LDAP, "ldap");
		}
		return new ResolvedMechanism(AuthProviderType.INTERNAL, "internal");
	}

}
