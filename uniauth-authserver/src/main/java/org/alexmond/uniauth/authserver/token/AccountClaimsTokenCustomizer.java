package org.alexmond.uniauth.authserver.token;

import java.util.List;
import java.util.Set;

import org.alexmond.uniauth.authserver.user.AccountStore;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.StringUtils;

/**
 * Puts what this provider knows about an account into its ID token.
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
public class AccountClaimsTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final AccountStore accounts;

	public AccountClaimsTokenCustomizer(AccountStore accounts) {
		this.accounts = accounts;
	}

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
		addProfileClaims(context, principal.getName());
	}

	/**
	 * The standard OIDC claims, gated on the scopes actually granted.
	 *
	 * <p>
	 * Gated rather than always emitted, because that is what makes them mean anything: a
	 * client that did not ask for {@code email} has not been authorised to learn one, and
	 * a provider that hands it over regardless has turned a scope into decoration. It
	 * also makes this provider behave like the real ones the demo sits beside, so what a
	 * relying party sees here is what it will see from Google.
	 */
	private void addProfileClaims(JwtEncodingContext context, String username) {
		AccountStore.Profile profile = this.accounts.profileOf(username);
		Set<String> scopes = context.getAuthorizedScopes();
		if (scopes.contains(OidcScopes.PROFILE) && StringUtils.hasText(profile.name())) {
			context.getClaims().claim(StandardClaimNames.NAME, profile.name());
		}
		if (scopes.contains(OidcScopes.EMAIL) && StringUtils.hasText(profile.email())) {
			context.getClaims().claim(StandardClaimNames.EMAIL, profile.email());
			// Always alongside the address, never on its own: "unverified" is a useful
			// answer, but only when there is something it is about.
			context.getClaims().claim(StandardClaimNames.EMAIL_VERIFIED, profile.emailVerified());
		}
	}

}
