package org.alexmond.uniauth.approval;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.util.ClassUtils;

/**
 * Copies an {@code Authentication}, keeping its concrete type, with different
 * authorities.
 *
 * <p>
 * The type matters: it is how {@link org.alexmond.uniauth.provider.MechanismResolver}
 * works out which provider answered, and it is what an application's own code sees.
 * Flattening every principal into a {@code UsernamePasswordAuthenticationToken} to attach
 * a role would quietly destroy that, so each known type is rebuilt through its own
 * constructor and anything unrecognised is returned unchanged.
 *
 * <p>
 * Returning the original rather than throwing is deliberate. A custom
 * {@code Authentication} means a custom mechanism, and refusing to serve the request
 * would be a worse answer than not granting a role the application may not be using.
 */
final class Authentications {

	private static final boolean SAML_PRESENT = ClassUtils
		.isPresent("org.springframework.security.saml2.provider.service.authentication.Saml2Authentication", null);

	private static final boolean OAUTH2_PRESENT = ClassUtils
		.isPresent("org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken", null);

	private Authentications() {
	}

	static Authentication withAuthorities(Authentication original, Collection<GrantedAuthority> authorities) {
		if (OAUTH2_PRESENT) {
			Authentication rebuilt = Oauth2.rebuild(original, authorities);
			if (rebuilt != null) {
				return copyDetails(original, rebuilt);
			}
		}
		if (SAML_PRESENT) {
			Authentication rebuilt = Saml.rebuild(original, authorities);
			if (rebuilt != null) {
				return copyDetails(original, rebuilt);
			}
		}
		if (original instanceof UsernamePasswordAuthenticationToken token) {
			return copyDetails(original,
					new UsernamePasswordAuthenticationToken(token.getPrincipal(), token.getCredentials(), authorities));
		}
		return original;
	}

	private static Authentication copyDetails(Authentication original, Authentication rebuilt) {
		if (rebuilt instanceof org.springframework.security.authentication.AbstractAuthenticationToken token) {
			token.setDetails(original.getDetails());
		}
		return rebuilt;
	}

	/** Isolated so the OAuth2 types load only when the jar is on the classpath. */
	private static final class Oauth2 {

		static Authentication rebuild(Authentication original, Collection<GrantedAuthority> authorities) {
			if (original instanceof OAuth2AuthenticationToken token
					&& token.getPrincipal() instanceof OAuth2User user) {
				// The registration id has to survive: it is the provider half of the
				// approval key, so losing it would unapprove the principal on the next
				// request and loop.
				return new OAuth2AuthenticationToken(user, authorities, token.getAuthorizedClientRegistrationId());
			}
			return null;
		}

	}

	/** Isolated for the same reason, since SAML is an optional mechanism too. */
	private static final class Saml {

		static Authentication rebuild(Authentication original, Collection<GrantedAuthority> authorities) {
			if (original instanceof Saml2Authentication token) {
				return new Saml2Authentication(
						(org.springframework.security.core.AuthenticatedPrincipal) token.getPrincipal(),
						token.getSaml2Response(), authorities);
			}
			return null;
		}

	}

}
