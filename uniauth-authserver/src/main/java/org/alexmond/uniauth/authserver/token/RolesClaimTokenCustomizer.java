package org.alexmond.uniauth.authserver.token;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Puts the account's roles into the ID token as a {@code roles} claim.
 *
 * <p>
 * Without this an OIDC login tells a client <em>who</em> signed in and nothing about what
 * they are entitled to: Spring Security gives such a user {@code OIDC_USER} and a
 * {@code SCOPE_*} per granted scope, and no roles at all. A client whose pages require a
 * role would then reject every account the provider vouches for — which is exactly how
 * this was found, with the admin console 403ing its own administrators.
 *
 * <p>
 * The authority names go in <em>verbatim</em>, {@code ROLE_} prefix included. Stripping
 * the prefix here and re-adding it in every client is a convention two sides have to
 * agree on silently; sending what Spring Security actually uses means a client maps the
 * claim straight to
 * {@link org.springframework.security.core.authority.SimpleGrantedAuthority} with nothing
 * to get wrong.
 *
 * <p>
 * ID token only, deliberately. The access token is a bearer credential for calling APIs,
 * and this provider fronts none that authorize by role — putting roles there would be
 * publishing an authorization decision nothing consumes.
 */
public class RolesClaimTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	@Override
	public void customize(JwtEncodingContext context) {
		if (!OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			return;
		}
		Authentication principal = context.getPrincipal();
		if (principal == null) {
			// No user behind the token — client_credentials, for instance. There are no
			// roles to report and inventing an empty claim would suggest there were.
			return;
		}
		List<String> roles = principal.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.filter((authority) -> authority.startsWith("ROLE_"))
			.sorted()
			.toList();
		if (!roles.isEmpty()) {
			context.getClaims().claim("roles", roles);
		}
	}

}
