package org.alexmond.uniauth.examples.session;

import org.alexmond.uniauth.provider.AuthProviderType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Works out which of the four mechanisms authenticated the current session.
 *
 * <p>
 * There is no flag on {@code Authentication} saying "LDAP did this", so the answer is
 * read off the concrete types Spring Security leaves behind. The redirect-based
 * mechanisms are unambiguous — each has its own token class. The two form-based ones both
 * produce a {@code UsernamePasswordAuthenticationToken}, so they are told apart by their
 * principal: only {@code LdapAuthenticationProvider} returns an {@link LdapUserDetails}.
 *
 * <p>
 * This lives in the sample rather than the starter on purpose: it is a display concern,
 * and promoting it would widen the library's API before anything depends on it.
 */
@Component
public class SessionFactsResolver {

	public SessionFacts resolve(Authentication authentication) {
		List<String> authorities = authentication.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.toList();
		String tokenType = authentication.getClass().getSimpleName();

		if (authentication instanceof OAuth2AuthenticationToken oauth2) {
			return new SessionFacts(authentication.getName(), AuthProviderType.OAUTH2,
					oauth2.getAuthorizedClientRegistrationId(), authorities, tokenType,
					detailsOf(oauth2.getPrincipal()));
		}
		if (authentication instanceof Saml2Authentication saml2) {
			String registrationId = null;
			if (saml2.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal) {
				registrationId = principal.getRelyingPartyRegistrationId();
			}
			return new SessionFacts(authentication.getName(), AuthProviderType.SAML, registrationId, authorities,
					tokenType, detailsOf(saml2.getPrincipal()));
		}

		Object principal = authentication.getPrincipal();
		AuthProviderType answeredBy = (principal instanceof LdapUserDetails) ? AuthProviderType.LDAP
				: AuthProviderType.INTERNAL;
		return new SessionFacts(authentication.getName(), answeredBy, null, authorities, tokenType,
				detailsOf(principal));
	}

	private List<SessionFacts.Detail> detailsOf(Object principal) {
		List<SessionFacts.Detail> details = new ArrayList<>();
		if (principal instanceof LdapUserDetails ldap) {
			details.add(new SessionFacts.Detail("dn", ldap.getDn()));
		}
		if (principal instanceof OidcUser oidc) {
			addAll(details, oidc.getClaims());
		}
		else if (principal instanceof OAuth2User oauth2) {
			addAll(details, oauth2.getAttributes());
		}
		else if (principal instanceof Saml2AuthenticatedPrincipal saml2) {
			saml2.getAttributes().forEach((key, values) -> details.add(new SessionFacts.Detail(key, join(values))));
		}
		if (principal instanceof UserDetails user) {
			details.add(new SessionFacts.Detail("account non-expired", String.valueOf(user.isAccountNonExpired())));
			details.add(
					new SessionFacts.Detail("credentials non-expired", String.valueOf(user.isCredentialsNonExpired())));
		}
		return List.copyOf(details);
	}

	private void addAll(List<SessionFacts.Detail> details, Map<String, Object> source) {
		source.forEach((key, value) -> details.add(new SessionFacts.Detail(key, String.valueOf(value))));
	}

	private String join(List<Object> values) {
		return values.stream().map(String::valueOf).reduce((left, right) -> left + ", " + right).orElse("");
	}

}
