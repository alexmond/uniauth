package org.alexmond.uniauth.autoconfigure;

import java.util.ArrayList;
import java.util.List;

import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProvider;
import org.alexmond.uniauth.provider.AuthProviderBrand;
import org.alexmond.uniauth.provider.AuthProviderType;
import org.alexmond.uniauth.provider.RedirectMechanism;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

/**
 * SAML 2.0, kept in one place so the rest of the starter never names its types.
 *
 * <p>
 * Everything SAML-specific lives here: the repository type, the registration type, and
 * the {@code saml2Login}/{@code saml2Logout} calls. That is what allows
 * {@code spring-boot-starter-security-saml2} to be an optional dependency — and with it,
 * the Shibboleth repository, which every consumer previously had to declare because
 * OpenSAML is not published to Maven Central, whether or not they used SAML.
 */
class SamlMechanism implements RedirectMechanism {

	private final UniAuthProperties properties;

	private final ObjectProvider<RelyingPartyRegistrationRepository> relyingParties;

	SamlMechanism(UniAuthProperties properties, ObjectProvider<RelyingPartyRegistrationRepository> relyingParties) {
		this.properties = properties;
		this.relyingParties = relyingParties;
	}

	@Override
	public List<AuthProvider> providers() {
		if (!this.properties.getSaml().isEnabled()) {
			return List.of();
		}
		List<AuthProvider> found = new ArrayList<>();
		// Enumerated by testing for Iterable, which the in-memory repository Boot builds
		// is. A custom repository is not, so its registrations still work in the chain
		// but
		// cannot be listed — the limitation the registry already documents.
		if (this.relyingParties.getIfAvailable() instanceof Iterable<?> iterable) {
			for (Object candidate : iterable) {
				RelyingPartyRegistration registration = (RelyingPartyRegistration) candidate;
				found.add(new AuthProvider(registration.getRegistrationId(), AuthProviderType.SAML,
						AuthProviderBrand.GENERIC, capitalize(registration.getRegistrationId()),
						"/saml2/authenticate/" + registration.getRegistrationId(), false));
			}
		}
		return List.copyOf(found);
	}

	@Override
	public void install(HttpSecurity http, String loginPage, String defaultSuccessUrl) throws Exception {
		http.saml2Login((saml2) -> saml2.loginPage(loginPage).defaultSuccessUrl(defaultSuccessUrl, true));
		http.saml2Logout((logout) -> {
		});
	}

	private static String capitalize(String id) {
		if (id == null || id.isEmpty()) {
			return id;
		}
		return Character.toUpperCase(id.charAt(0)) + id.substring(1);
	}

}
