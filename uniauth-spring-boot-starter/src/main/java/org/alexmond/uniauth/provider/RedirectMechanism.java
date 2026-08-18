package org.alexmond.uniauth.provider;

import java.util.List;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * A redirect-based mechanism, contributed by whichever of them is on the classpath.
 *
 * <p>
 * This exists so that OAuth2 and SAML can be <em>optional</em> dependencies. Both were
 * compile-scope for the same reason LDAP was: the registry named
 * {@code RelyingPartyRegistrationRepository} as a field and a constructor parameter, and
 * the filter chain named it again in its own signature — and a type named in a signature
 * has to be loadable, so the jar had to be there whether the mechanism was used or not.
 * For SAML that also dragged the Shibboleth repository into every consumer's build,
 * because OpenSAML is not on Maven Central, for a mechanism most of them never enable.
 *
 * <p>
 * So neither class names those types any more. Each mechanism contributes an
 * implementation of this from a {@code @ConditionalOnClass} configuration, and everything
 * general is expressed in terms of {@link AuthProvider} — which names nothing
 * mechanism-specific.
 *
 * <p>
 * Internal: implemented by the starter for the mechanisms it supports. It is not an
 * extension point for adding new ones — that would mean owning the login flow, the
 * callback and the token handling, which is Spring Security's job rather than this
 * library's.
 */
public interface RedirectMechanism {

	/**
	 * The registrations that can be offered on the chooser right now.
	 * @return one entry per registration, or empty when none are configured
	 */
	List<AuthProvider> providers();

	/**
	 * Installs this mechanism's login onto the shared chain.
	 *
	 * <p>
	 * Only called when {@link #providers()} is non-empty: a login installed with no
	 * registration behind it would 404 its own callback.
	 * @param http the chain being built
	 * @param loginPage where an unauthenticated user is sent to choose
	 * @param defaultSuccessUrl where a successful sign-in lands
	 * @throws Exception if the mechanism cannot be installed
	 */
	void install(HttpSecurity http, String loginPage, String defaultSuccessUrl) throws Exception;

}
