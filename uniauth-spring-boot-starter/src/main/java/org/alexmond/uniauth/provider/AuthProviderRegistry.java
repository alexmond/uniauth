package org.alexmond.uniauth.provider;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

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

	private final ObjectProvider<ClientRegistrationRepository> clientRegistrations;

	private final ObjectProvider<RelyingPartyRegistrationRepository> relyingParties;

	/**
	 * Creates the registry.
	 * @param properties which mechanisms are switched on
	 * @param clientRegistrations OAuth2 registrations, absent when none are configured
	 * @param relyingParties SAML registrations, absent when none are configured
	 */
	public AuthProviderRegistry(UniAuthProperties properties,
			ObjectProvider<ClientRegistrationRepository> clientRegistrations,
			ObjectProvider<RelyingPartyRegistrationRepository> relyingParties) {
		this.properties = properties;
		this.clientRegistrations = clientRegistrations;
		this.relyingParties = relyingParties;
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
		if (properties.getOauth2().isEnabled()) {
			ClientRegistrationRepository repository = clientRegistrations.getIfAvailable();
			if (repository instanceof Iterable<?> iterable) {
				for (Object candidate : iterable) {
					ClientRegistration registration = (ClientRegistration) candidate;
					redirect.add(new AuthProvider(registration.getRegistrationId(), AuthProviderType.OAUTH2,
							AuthProviderBrand.detect(registration), displayNameOf(registration),
							"/oauth2/authorization/" + registration.getRegistrationId(), isOidc(registration)));
				}
			}
		}
		if (properties.getSaml().isEnabled()) {
			RelyingPartyRegistrationRepository repository = relyingParties.getIfAvailable();
			if (repository instanceof Iterable<?> iterable) {
				for (Object candidate : iterable) {
					RelyingPartyRegistration registration = (RelyingPartyRegistration) candidate;
					redirect.add(new AuthProvider(registration.getRegistrationId(), AuthProviderType.SAML,
							AuthProviderBrand.GENERIC, capitalize(registration.getRegistrationId()),
							"/saml2/authenticate/" + registration.getRegistrationId(), false));
				}
			}
		}
		return List.copyOf(redirect);
	}

	/**
	 * Whether the username/password form should be rendered at all.
	 * @return {@code true} when at least one form-based mechanism is enabled
	 */
	public boolean hasFormProvider() {
		return !formProviders().isEmpty();
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
	 * Whether the provider issues an id_token, which decides whether the principal
	 * arrives as an {@code OidcUser} carrying claims or as a bare {@code OAuth2User}
	 * assembled from a userinfo call. The {@code openid} scope is the request for one,
	 * and its absence is why GitHub logins carry no claims and have nothing to support
	 * RP-initiated logout.
	 */
	private static boolean isOidc(ClientRegistration registration) {
		return registration.getScopes() != null && registration.getScopes().contains("openid");
	}

	/**
	 * {@code ClientRegistration} already defaults an unset client name to the
	 * registration id, so an id-equal name means nothing was configured — capitalize it
	 * rather than render a bare lowercase slug as a button label.
	 */
	private static String displayNameOf(ClientRegistration registration) {
		String name = registration.getClientName();
		if (name == null || name.isBlank() || name.equals(registration.getRegistrationId())) {
			return capitalize(registration.getRegistrationId());
		}
		return name;
	}

	private static String capitalize(String value) {
		if (value == null || value.isEmpty()) {
			return value;
		}
		return Character.toUpperCase(value.charAt(0)) + value.substring(1);
	}

}
