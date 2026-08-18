package org.alexmond.uniauth.provider;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.springframework.beans.factory.ObjectProvider;

import java.util.ArrayList;
import java.util.List;

/**
 * Assembles the list of currently selectable providers.
 *
 * <p>
 * This is the single place that answers "what can a user actually sign in with right
 * now", and both the chooser page and the providers endpoint read from it. The OAuth2 and
 * SAML entries are discovered from the registration repositories rather than from
 * UniAuth's own properties, so they stay in step with whatever Spring Boot bound under
 * {@code spring.security.*}.
 *
 * <p>
 * Enumeration only works for the in-memory repository implementations, which are what
 * Boot's property binding produces. A custom repository (a database-backed one, say) is
 * not iterable — in that case the mechanism is still wired into the filter chain, but its
 * buttons cannot be listed here and the consuming app must render its own.
 */
public class AuthProviderRegistry {

	private final UniAuthProperties properties;

	private final ObjectProvider<RedirectMechanism> redirectMechanisms;

	/**
	 * Creates the registry.
	 * @param properties which mechanisms are switched on
	 * @param redirectMechanisms the redirect-based mechanisms present on the classpath.
	 * Passed as contributors rather than as their own repository types, so that this
	 * class names nothing mechanism-specific and OAuth2 and SAML can both be optional
	 * dependencies
	 */
	public AuthProviderRegistry(UniAuthProperties properties, ObjectProvider<RedirectMechanism> redirectMechanisms) {
		this.properties = properties;
		this.redirectMechanisms = redirectMechanisms;
	}

	/**
	 * Every selectable provider, form-based ones first.
	 * @return an immutable list, in the order a chooser should render it
	 */
	public List<AuthProvider> providers() {
		List<AuthProvider> all = new ArrayList<>(formProviders());
		all.addAll(redirectProviders());
		return List.copyOf(all);
	}

	/**
	 * Providers answering the shared username/password form.
	 * @return an immutable list; more than one entry means the same form resolves through
	 * several {@code AuthenticationProvider}s in turn
	 */
	public List<AuthProvider> formProviders() {
		List<AuthProvider> form = new ArrayList<>();
		if (properties.getInternal().isEnabled()) {
			form.add(new AuthProvider("internal", AuthProviderType.INTERNAL, AuthProviderBrand.GENERIC,
					properties.getInternal().getDisplayName(), null, false));
		}
		if (properties.getLdap().isEnabled()) {
			form.add(new AuthProvider("ldap", AuthProviderType.LDAP, AuthProviderBrand.GENERIC,
					properties.getLdap().getDisplayName(), null, false));
		}
		return List.copyOf(form);
	}

	/**
	 * Providers rendered as their own button, each starting a redirect flow.
	 * @return an immutable list, one entry per OAuth2 and SAML registration that could be
	 * enumerated — see the note on this class about non-iterable repositories
	 */
	public List<AuthProvider> redirectProviders() {
		List<AuthProvider> redirect = new ArrayList<>();
		this.redirectMechanisms.orderedStream().forEach((mechanism) -> redirect.addAll(mechanism.providers()));
		return List.copyOf(redirect);
	}

	/**
	 * Whether nothing is configured — the login page says so rather than showing an empty
	 * box.
	 * @return {@code true} when no mechanism at all is available
	 */
	public boolean isEmpty() {
		return providers().isEmpty();
	}

	/**
	 * Whether the username/password form should be rendered at all.
	 * @return {@code true} when at least one form-based mechanism is enabled
	 */
	public boolean hasFormProvider() {
		return !formProviders().isEmpty();
	}

}
