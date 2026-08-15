package org.alexmond.uniauth.examples.session;

import org.alexmond.uniauth.provider.AuthProviderType;

import java.util.List;

/**
 * What the application knows about the current sign-in, flattened for display.
 *
 * @param name the authenticated principal's name
 * @param answeredBy which mechanism authenticated this session
 * @param registrationId the OAuth2/SAML registration that answered, or {@code null} for
 * the form-based mechanisms
 * @param authorities granted authorities, in declaration order
 * @param tokenType the concrete {@code Authentication} implementation, which is the
 * evidence {@code answeredBy} is derived from
 * @param details name/value pairs pulled off the principal — claims for OIDC, attributes
 * for SAML, the DN for LDAP
 */
public record SessionFacts(String name, AuthProviderType answeredBy, String registrationId, List<String> authorities,
		String tokenType, List<Detail> details) {

	/** One name/value row in the principal inspector. */
	public record Detail(String key, String value) {
	}

}
