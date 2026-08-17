package org.alexmond.uniauth.oauth2;

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.regex.Pattern;

/**
 * Validates a Microsoft Entra ID id_token when the registration points at a shared
 * (multi-tenant) endpoint.
 *
 * <p>
 * OpenID Connect requires the {@code iss} claim to match the issuer from discovery
 * exactly. Entra breaks that for {@code common} and {@code organizations}: discovery
 * advertises an issuer containing the literal placeholder <code>{tenantid}</code>, while
 * every id_token carries the caller's real tenant. The exact-match rule therefore rejects
 * every token.
 *
 * <p>
 * Rather than reimplement id_token validation, this keeps Spring's
 * {@link OidcIdTokenValidator} and narrows the substitution to one rule. Spring skips its
 * issuer comparison when the registration carries no issuer, so the delegate is built
 * over a copy with the issuer removed and still performs every other check — required
 * claims, audience, authorized party, expiry, issued-at. This class then adds the issuer
 * check Entra actually permits: same host as the configured endpoint, a GUID tenant, and
 * the v2.0 suffix.
 *
 * <p>
 * <strong>This is a real loosening.</strong> Any Entra tenant can now sign in, not only
 * yours. If that is not what you want, authorize on the {@code tid} claim afterwards. The
 * host is taken from the registration rather than hard-coded so sovereign clouds (US
 * Government, China, Germany) work without further configuration.
 */
public final class MicrosoftMultiTenantIdTokenValidator implements OAuth2TokenValidator<Jwt> {

	private static final Pattern TENANT_PATH = Pattern
		.compile("^/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/v2\\.0/?$");

	private final OAuth2TokenValidator<Jwt> delegate;

	private final String expectedHost;

	/**
	 * Creates a validator for one registration.
	 * @param registration the Microsoft registration whose issuer check is being widened;
	 * a copy with the issuer removed is handed to Spring's own validator, so every other
	 * check it performs stays intact
	 */
	public MicrosoftMultiTenantIdTokenValidator(ClientRegistration registration) {
		this.delegate = new OidcIdTokenValidator(withoutIssuer(registration));
		this.expectedHost = hostOf(registration.getProviderDetails().getAuthorizationUri());
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt idToken) {
		// The issuer is checked before delegating, not after: reading an unparseable iss
		// throws, and the delegate reads it first thing.
		URL issuer = issuerOf(idToken);
		if (issuer == null || !isTenantIssuer(issuer)) {
			return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_id_token",
					"The ID Token issuer is not a Microsoft Entra tenant of " + this.expectedHost + ": "
							+ idToken.getClaims().get("iss"),
					"https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"));
		}
		return this.delegate.validate(idToken);
	}

	/**
	 * {@code Jwt} converts {@code iss} to a {@link URL} on read and throws if it will not
	 * parse. A token whose issuer is not even a URL is simply invalid, so report that
	 * rather than let the exception escape into the filter chain.
	 */
	private static URL issuerOf(Jwt idToken) {
		try {
			return idToken.getIssuer();
		}
		catch (RuntimeException ex) {
			return null;
		}
	}

	private boolean isTenantIssuer(URL issuer) {
		if (!"https".equals(issuer.getProtocol())) {
			return false;
		}
		if (this.expectedHost == null || !this.expectedHost.equalsIgnoreCase(issuer.getHost())) {
			return false;
		}
		return TENANT_PATH.matcher(issuer.getPath()).matches();
	}

	private static ClientRegistration withoutIssuer(ClientRegistration registration) {
		return ClientRegistration.withClientRegistration(registration).issuerUri(null).build();
	}

	private static String hostOf(String uri) {
		if (uri == null) {
			return null;
		}
		try {
			return new URI(uri).getHost();
		}
		catch (URISyntaxException ex) {
			return null;
		}
	}

}
