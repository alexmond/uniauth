package org.alexmond.uniauth.provider;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;

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

	private final ObjectProvider<AuthenticationProvider> authenticationProviders;

	private final ObjectProvider<UserDetailsService> userDetailsServices;

	/**
	 * Creates the registry.
	 * @param properties which mechanisms are switched on
	 * @param redirectMechanisms the redirect-based mechanisms present on the classpath.
	 * Passed as contributors rather than as their own repository types, so that this
	 * class names nothing mechanism-specific and OAuth2 and SAML can both be optional
	 * dependencies
	 * @param authenticationProviders every {@code AuthenticationProvider} bean in the
	 * context. Consulted only to answer whether a password form is worth showing — when
	 * neither of UniAuth's own form mechanisms is enabled, UniAuth contributes none of
	 * these, so anything here belongs to the application
	 * @param userDetailsServices every {@code UserDetailsService} bean, for the same
	 * question: an application can bring one of those instead and let Spring Security
	 * build the provider around it
	 */
	public AuthProviderRegistry(UniAuthProperties properties, ObjectProvider<RedirectMechanism> redirectMechanisms,
			ObjectProvider<AuthenticationProvider> authenticationProviders,
			ObjectProvider<UserDetailsService> userDetailsServices) {
		this.properties = properties;
		this.redirectMechanisms = redirectMechanisms;
		this.authenticationProviders = authenticationProviders;
		this.userDetailsServices = userDetailsServices;
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
	 *
	 * <p>
	 * The form counts even though it has no named entry. An application whose accounts
	 * are its own appears nowhere in {@link #providers()}, so without that second term
	 * its login page would carry a working password form underneath a notice saying there
	 * was nothing to sign in with.
	 * @return {@code true} when no mechanism at all is available
	 */
	public boolean isEmpty() {
		return providers().isEmpty() && !hasFormProvider();
	}

	/**
	 * Whether the username/password form should be rendered, and the form-login filter
	 * installed behind it.
	 *
	 * <p>
	 * This used to be {@code !formProviders().isEmpty()} — the two configuration flags
	 * and nothing else. So it answered "can a username and password be entered here?" by
	 * looking only at whether <em>UniAuth's own</em> mechanisms were enabled, never at
	 * whether the application had registered something that would happily authenticate
	 * one. An application holding its credentials somewhere else got the redirect buttons
	 * and no form; and because this same answer gates {@code http.formLogin}, there was
	 * nothing listening on the login path either. The form was not broken, it did not
	 * exist (#9).
	 *
	 * <p>
	 * The remaining escape hatch is {@code uniauth.form.enabled}, for what cannot be
	 * detected: an {@code AuthenticationManager} bean is neither of the two types looked
	 * at here and does not announce itself.
	 * @return {@code true} when a form-based mechanism is enabled, or the application
	 * brought accounts of its own, unless {@code uniauth.form.enabled} says otherwise
	 */
	public boolean hasFormProvider() {
		Boolean configured = this.properties.getForm().getEnabled();
		if (configured != null) {
			return configured;
		}
		// Short-circuits before touching the context in the ordinary case, so enabling
		// uniauth.internal does not drag an application's beans into existence early.
		return !formProviders().isEmpty() || applicationBringsItsOwnAccounts();
	}

	/**
	 * Whether anything in the context can answer a username and password.
	 *
	 * <p>
	 * Only ever asked when neither of UniAuth's form mechanisms is on, and UniAuth
	 * declares both of these bean types only for those mechanisms — so there is no need
	 * to tell its own contributions apart from the application's. There are none.
	 * @return {@code true} when the application registered a provider or a user-details
	 * service
	 */
	private boolean applicationBringsItsOwnAccounts() {
		return this.authenticationProviders.stream().findAny().isPresent()
				|| this.userDetailsServices.stream().findAny().isPresent();
	}

}
