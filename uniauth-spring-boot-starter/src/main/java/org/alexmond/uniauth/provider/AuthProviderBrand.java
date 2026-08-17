package org.alexmond.uniauth.provider;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;

import java.util.Locale;

/**
 * Who is on the other end of a redirect-based sign-in.
 *
 * <p>
 * Brand is deliberately <em>not</em> part of {@link AuthProviderType}. That enum answers
 * "how does this mechanism talk", which is what decides the filter wiring; this one
 * answers "whose service is it", which decides presentation — an icon, and in Google's
 * and Apple's case a button treatment their brand guidelines actually mandate.
 *
 * <p>
 * Brand is a poor guide to behaviour, and the reason is worth stating: GitHub differs
 * from Google not because of who they are but because GitHub is plain OAuth2 while Google
 * is OpenID Connect. {@link AuthProvider#oidc()} carries that difference. Reach for the
 * flag when you mean capability and for the brand only when you mean the logo.
 */
public enum AuthProviderBrand {

	/** OpenID Connect. Yields an {@code OidcUser} with claims. */
	GOOGLE("Google", "accounts.google.com"),

	/**
	 * OpenID Connect. Multi-tenant deployments need
	 * {@code uniauth.oauth2.microsoft.multi-tenant}.
	 */
	MICROSOFT("Microsoft", "login.microsoftonline.com"),

	/**
	 * Plain OAuth2 — no id_token, no claims. Volunteers no email address either; see
	 * {@code uniauth.oauth2.github.fetch-email}.
	 */
	GITHUB("GitHub", "github.com"),

	/**
	 * Recognised for rendering only. Sign in with Apple is <em>not supported</em>: it
	 * requires a generated ES256 client secret and {@code ClientRegistration} accepts
	 * only a static one.
	 */
	APPLE("Apple", "appleid.apple.com"),

	/** Plain OAuth2. */
	FACEBOOK("Facebook", "facebook.com"),

	/** OpenID Connect, and the usual stand-in for any discovery-based IdP. */
	OKTA("Okta", "okta.com"),

	/** Anything unrecognised: a self-hosted Keycloak, an in-house IdP, a SAML party. */
	GENERIC("", null);

	private final String displayName;

	private final String host;

	AuthProviderBrand(String displayName, String host) {
		this.displayName = displayName;
		this.host = host;
	}

	/**
	 * Official name of the service, spelled as the vendor spells it.
	 * @return the display name, or an empty string for {@link #GENERIC}
	 */
	public String displayName() {
		return this.displayName;
	}

	/**
	 * Identifies the brand behind a registration.
	 *
	 * <p>
	 * The registration id is tried first because Spring Boot already keys
	 * {@code CommonOAuth2Provider} off it, so an id of {@code google} is a deliberate
	 * choice rather than a coincidence. Endpoint hosts are the fallback, which is what
	 * catches a registration named for its role — {@code corporate-sso} pointing at Entra
	 * ID, say.
	 * @param registration the registration to inspect, may be {@code null}
	 * @return the matching brand, never {@code null}
	 */
	public static AuthProviderBrand detect(ClientRegistration registration) {
		if (registration == null) {
			return GENERIC;
		}
		String id = registration.getRegistrationId();
		if (StringUtils.hasText(id)) {
			for (AuthProviderBrand brand : values()) {
				if (brand != GENERIC && brand.name().equals(id.toUpperCase(Locale.ROOT))) {
					return brand;
				}
			}
		}
		String endpoints = String.join(" ", nullSafe(registration.getProviderDetails().getIssuerUri()),
				nullSafe(registration.getProviderDetails().getAuthorizationUri()),
				nullSafe(registration.getProviderDetails().getUserInfoEndpoint().getUri()));
		for (AuthProviderBrand brand : values()) {
			if (brand.host != null && endpoints.contains(brand.host)) {
				return brand;
			}
		}
		return GENERIC;
	}

	private static String nullSafe(String value) {
		return (value != null) ? value : "";
	}

}
