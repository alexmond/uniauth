package org.alexmond.uniauth.admin;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

/**
 * Turns the provider's {@code roles} claim into authorities this console authorizes on.
 *
 * <p>
 * An OIDC login arrives with {@code OIDC_USER} and a {@code SCOPE_*} per granted scope,
 * and no roles — Spring Security has no way to know what a role means at a given
 * provider. Every page here needs {@code ROLE_ADMIN}, so without this mapping an OIDC
 * sign-in succeeds and then 403s on the first page, which reads as a broken console
 * rather than as a permissions decision.
 *
 * <p>
 * <strong>This is a privilege boundary, and it runs in one direction only.</strong> The
 * console holds a token that creates accounts <em>at the provider</em>, including
 * accounts with {@code ROLE_ADMIN}. Admitting provider accounts here therefore closes a
 * loop: anyone who is an administrator at the provider can administer the provider. That
 * is a deliberate choice for a demo where both are the same operator, and it is the wrong
 * choice anywhere the two populations are meant to be separate — there, either disable
 * this registration or map a claim the provider does not let its own administrators grant
 * themselves.
 *
 * <p>
 * Only {@code ROLE_}-prefixed values from the claim are honoured. A provider that sends
 * something else is not silently granted an authority of its own choosing.
 */
public class ConsoleAuthoritiesMapper implements GrantedAuthoritiesMapper {

	@Override
	public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
		Set<GrantedAuthority> mapped = new LinkedHashSet<>(authorities);
		for (GrantedAuthority authority : authorities) {
			if (authority instanceof OidcUserAuthority oidc) {
				List<String> roles = oidc.getIdToken().getClaimAsStringList("roles");
				if (roles != null) {
					roles.stream()
						.filter((role) -> role.startsWith("ROLE_"))
						.map(SimpleGrantedAuthority::new)
						.forEach(mapped::add);
				}
			}
		}
		return mapped;
	}

}
