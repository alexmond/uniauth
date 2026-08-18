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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * OAuth2 and OpenID Connect, kept in one place for the same reason as
 * {@link SamlMechanism}: so nothing general names its types, and the dependency can be
 * optional.
 */
class Oauth2Mechanism implements RedirectMechanism {

	private final UniAuthProperties properties;

	private final ObjectProvider<ClientRegistrationRepository> clientRegistrations;

	Oauth2Mechanism(UniAuthProperties properties, ObjectProvider<ClientRegistrationRepository> clientRegistrations) {
		this.properties = properties;
		this.clientRegistrations = clientRegistrations;
	}

	@Override
	public List<AuthProvider> providers() {
		if (!this.properties.getOauth2().isEnabled()) {
			return List.of();
		}
		List<AuthProvider> found = new ArrayList<>();
		if (this.clientRegistrations.getIfAvailable() instanceof Iterable<?> iterable) {
			for (Object candidate : iterable) {
				ClientRegistration registration = (ClientRegistration) candidate;
				found.add(new AuthProvider(registration.getRegistrationId(), AuthProviderType.OAUTH2,
						AuthProviderBrand.detect(registration), displayNameOf(registration),
						"/oauth2/authorization/" + registration.getRegistrationId(), isOidc(registration)));
			}
		}
		return List.copyOf(found);
	}

	@Override
	public void install(HttpSecurity http, String loginPage, String defaultSuccessUrl) throws Exception {
		http.oauth2Login((oauth2) -> oauth2.loginPage(loginPage).defaultSuccessUrl(defaultSuccessUrl, true));
	}

	/**
	 * Whether the provider issues an id_token, which decides whether the principal
	 * arrives as an {@code OidcUser} carrying claims or as a bare {@code OAuth2User}. The
	 * {@code openid} scope is the request for one.
	 */
	private static boolean isOidc(ClientRegistration registration) {
		return registration.getScopes() != null && registration.getScopes().contains("openid");
	}

	private static String displayNameOf(ClientRegistration registration) {
		String name = registration.getClientName();
		if (name == null || name.isBlank() || name.equals(registration.getRegistrationId())) {
			return capitalize(registration.getRegistrationId());
		}
		return name;
	}

	private static String capitalize(String id) {
		if (id == null || id.isEmpty()) {
			return id;
		}
		return Character.toUpperCase(id.charAt(0)) + id.substring(1);
	}

}
