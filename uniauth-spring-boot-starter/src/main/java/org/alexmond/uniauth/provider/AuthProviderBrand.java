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

	/**
	 * OpenID Connect. Yields an {@code OidcUser} with claims.
	 *
	 * <p>
	 * The only brand here whose guidelines forbid a specific rendering outright: "using
	 * 'Google' by itself as button text" is listed among the prohibitions, so the label
	 * is not a preference.
	 */
	GOOGLE("Google", "accounts.google.com", "Sign in with Google"),

	/**
	 * OpenID Connect. Multi-tenant deployments need
	 * {@code uniauth.oauth2.microsoft.multi-tenant}.
	 */
	MICROSOFT("Microsoft", "login.microsoftonline.com", "Sign in with Microsoft"),

	/**
	 * Plain OAuth2 — no id_token, no claims. Volunteers no email address either; see
	 * {@code uniauth.oauth2.github.fetch-email}.
	 */
	GITHUB("GitHub", "github.com", "Sign in with GitHub"),

	/**
	 * Recognised for rendering only. Sign in with Apple is <em>not supported</em>: it
	 * requires a generated ES256 client secret and {@code ClientRegistration} accepts
	 * only a static one.
	 *
	 * <p>
	 * Carries no call to action, unlike every other named brand here, and that is the
	 * reason: a compliant Apple button is a promise this library cannot keep. Apple's
	 * rules are also the one set not read from the vendor's own page — their guidelines
	 * were not reachable when the others were checked — so the treatment would be the
	 * least verified of the five as well as the only untestable one. It falls back to
	 * whatever the registration called itself. The treatment lands with the support, if
	 * Spring ever takes a non-static client secret.
	 */
	APPLE("Apple", "appleid.apple.com", ""),

	/**
	 * Plain OAuth2.
	 *
	 * <p>
	 * The one brand that cannot read like its neighbours. Its guidelines name two
	 * accepted labels — "Continue with Facebook" and "Login with Facebook" — and "Sign in
	 * with Facebook" is not among them, so the uniform wording every other brand here
	 * uses is unavailable. "Login with" is the closer of the two to it, which is why it
	 * is the one taken: one word differs instead of a different verb entirely.
	 */
	FACEBOOK("Facebook", "facebook.com", "Login with Facebook"),

	/**
	 * OpenID Connect, and the usual stand-in for any discovery-based IdP.
	 *
	 * <p>
	 * Deliberately carries no call to action. Okta is the vendor behind somebody else's
	 * identity provider, so "Sign in with Okta" would name the wrong organisation to the
	 * person reading the button — their employer's name is the useful one, and it arrives
	 * as the registration's client name.
	 */
	OKTA("Okta", "okta.com", ""),

	/** Anything unrecognised: a self-hosted Keycloak, an in-house IdP, a SAML party. */
	GENERIC("", null, "");

	private final String displayName;

	private final String host;

	private final String callToAction;

	AuthProviderBrand(String displayName, String host, String callToAction) {
		this.displayName = displayName;
		this.host = host;
		this.callToAction = callToAction;
	}

	/**
	 * Official name of the service, spelled as the vendor spells it.
	 * @return the display name, or an empty string for {@link #GENERIC}
	 */
	public String displayName() {
		return this.displayName;
	}

	/**
	 * The wording this brand requires on its own sign-in button.
	 *
	 * <p>
	 * Here rather than in a template because the template is replaceable: an application
	 * overriding {@code templates/uniauth/login.html} is the supported re-skin path, and
	 * the sample in this repository takes it. Compliance that lived in the markup would
	 * be lost by exactly the applications most likely to restyle the page, so it lives in
	 * the model and the markup renders whatever it is handed —
	 * {@link AuthProvider#buttonLabel()}.
	 *
	 * <p>
	 * Several of these are conditions attached to using the service rather than
	 * suggestions. Google's guidelines forbid "Google" alone as button text; Facebook
	 * names the labels it accepts. Microsoft's are guidance, and permit shortening to
	 * "Sign in" where there is no room. GitHub mandates no wording at all, and takes this
	 * one for consistency with its neighbours. Apple mandates one and is deliberately
	 * left out: see {@link #APPLE}.
	 *
	 * <p>
	 * They read alike on purpose, as far as the guidelines allow — buttons stacked in one
	 * column should not each phrase the same act differently. Identical wording is not
	 * reachable: the approved sets do not intersect, because Microsoft's does not include
	 * "Continue with" and Facebook's does not include "Sign in with". So "Sign in with X"
	 * is used wherever it is permitted, which is everywhere except Facebook, and Facebook
	 * takes the closest label it does permit.
	 * @return the required label, or an empty string when the brand mandates none, in
	 * which case the registration's own display name is the better answer
	 */
	public String callToAction() {
		return this.callToAction;
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
