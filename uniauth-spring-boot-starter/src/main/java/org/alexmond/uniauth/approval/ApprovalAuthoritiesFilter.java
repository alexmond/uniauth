package org.alexmond.uniauth.approval;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.alexmond.uniauth.provider.ResolvedMechanism;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Grants the roles an approver decided on.
 *
 * <p>
 * Approval used to be a boolean, which left a gap that only shows once an application's
 * rules use roles. A federated sign-in arrives with {@code OIDC_USER} and {@code SCOPE_*}
 * and no {@code ROLE_} anywhere, so an approved user cleared the gate, reached the
 * application, and was then refused by every {@code hasRole(...)} rule in it — while an
 * internal account had roles all along, from configuration. The two mechanisms were not
 * equivalent in what they could express, and the federated one is the one that needs it
 * more.
 *
 * <p>
 * The roles are granted here rather than at authentication time because that is what
 * makes approval take effect on the next request rather than the next sign-in — the same
 * promise the gate itself makes. It is also why {@code GrantedAuthoritiesMapper} cannot
 * do this job: it receives the authorities and not the principal, and roles are stored
 * per principal.
 *
 * <p>
 * The authentication is rebuilt rather than replaced with a generic token, because its
 * concrete type is load-bearing: {@link MechanismResolver} reads it to work out which
 * provider answered, and an application that flattened it into a
 * {@code UsernamePasswordAuthenticationToken} would silently lose that. A type this
 * filter does not know how to rebuild is left exactly as it was.
 */
public class ApprovalAuthoritiesFilter extends OncePerRequestFilter {

	private final ApprovalStore store;

	private final MechanismResolver mechanisms;

	private final UniAuthProperties properties;

	public ApprovalAuthoritiesFilter(ApprovalStore store, MechanismResolver mechanisms, UniAuthProperties properties) {
		this.store = store;
		this.mechanisms = mechanisms;
		this.properties = properties;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Authentication current = SecurityContextHolder.getContext().getAuthentication();
		Authentication granted = withApprovedRoles(current);
		if (granted != null) {
			SecurityContextHolder.getContext().setAuthentication(granted);
		}
		chain.doFilter(request, response);
	}

	/**
	 * @param current the authentication on the context
	 * @return a copy carrying the approved roles, or {@code null} to leave it alone
	 */
	private Authentication withApprovedRoles(Authentication current) {
		if (current == null || !current.isAuthenticated() || current instanceof AnonymousAuthenticationToken) {
			return null;
		}
		ResolvedMechanism mechanism = this.mechanisms.resolve(current);
		if (!this.properties.getApproval().getRequireFor().contains(mechanism.type())) {
			return null;
		}
		List<String> roles = this.store.find(ApprovalKey.of(mechanism, current))
			.filter((record) -> record.status() == ApprovalStatus.APPROVED)
			.map(ApprovalRecord::roles)
			.orElse(List.of());
		return granting(current, roles);
	}

	/**
	 * A copy of the authentication carrying these roles, or {@code null} when it already
	 * has every one of them.
	 *
	 * <p>
	 * Shared with {@link ApprovalAuthorizationManager}, which has to do the same thing at
	 * a different moment: roles an invitation grants are created <em>by</em> the
	 * authorization decision, so this filter has already run by the time they exist. Two
	 * copies of the prefixing rule would be two chances to disagree about what
	 * {@code hasRole()} compares against.
	 * @param current the authentication to extend
	 * @param roles the roles to grant, with or without the {@code ROLE_} prefix
	 * @return the extended authentication, or {@code null} if nothing was added
	 */
	static Authentication granting(Authentication current, List<String> roles) {
		if (roles.isEmpty()) {
			return null;
		}
		Set<GrantedAuthority> merged = new LinkedHashSet<>(current.getAuthorities());
		boolean added = false;
		for (String role : roles) {
			// Prefixed here so an approver types ADMIN and Spring sees ROLE_ADMIN, which
			// is what hasRole() compares against.
			GrantedAuthority authority = new SimpleGrantedAuthority(role.startsWith("ROLE_") ? role : "ROLE_" + role);
			added |= merged.add(authority);
		}
		// Rebuilding on every request would churn the session for no gain.
		return added ? Authentications.withAuthorities(current, merged) : null;
	}

}
