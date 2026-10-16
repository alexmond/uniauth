package org.alexmond.uniauth.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Adjusts UniAuth's chain itself — CSRF, headers, CORS, session management — without
 * owning it.
 *
 * <p>
 * {@link UniAuthAuthorizationCustomizer} answers "who may do what". Nothing answered the
 * rest of {@code HttpSecurity}, and the gap was not theoretical: the starter configures
 * no CSRF at all, so Spring Security's default applies — enabled, with a session-backed
 * token. An application whose front end posts JSON, or whose machine callers use HTTP
 * Basic, carries no such token, so enabling the starter turned working writes into 403s
 * with nothing failing at startup and nothing logged (#12). A plain HTML page served from
 * {@code static/} could not participate at all, because only a server-rendered form gets
 * the token injected — which makes a sign-out button on such a page a guaranteed 403.
 *
 * <p>
 * The only previous answer was to declare your own {@code SecurityFilterChain}, which
 * makes the starter back off entirely and costs every mechanism it wires. That is the
 * whole value of the library, so it is not an answer.
 *
 * <p>
 * Declare one or more as beans. Each is applied in
 * {@link org.springframework.core.Ordered} order, <em>after</em> everything UniAuth
 * configures and immediately before the chain is built, so a setting made here wins over
 * the starter's own.
 *
 * <pre>
 * &#64;Bean
 * UniAuthHttpSecurityCustomizer apiCsrf() {
 *     return (http) -&gt; http.csrf((csrf) -&gt; csrf
 *         .ignoringRequestMatchers("/api/**")
 *         .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
 * }
 * </pre>
 *
 * <p>
 * Being applied last is what makes it useful and also what makes it sharp. Two things to
 * leave alone:
 *
 * <ul>
 * <li><strong>Authorization rules.</strong> Calling {@code authorizeHttpRequests} again
 * here adds rules <em>after</em> the catch-all, where the first match has already won, so
 * they never run. {@link UniAuthAuthorizationCustomizer} exists for that and is applied
 * in the right place.</li>
 * <li><strong>Blanket {@code csrf(AbstractHttpConfigurer::disable)}.</strong> It switches
 * protection off for the login form and the logout endpoint too, which are state-changing
 * POSTs this library owns. Exempt the paths that genuinely cannot carry a token, and move
 * the token somewhere a front end can read it — see the CSRF section of the reference
 * documentation.</li>
 * </ul>
 */
@FunctionalInterface
public interface UniAuthHttpSecurityCustomizer {

	/**
	 * Adjusts the chain.
	 * @param http UniAuth's own {@code HttpSecurity}, fully configured; anything set here
	 * overrides what the starter set
	 * @throws Exception if the adjustment cannot be applied, which fails the context
	 * rather than installing a chain the application did not ask for
	 */
	void customize(HttpSecurity http) throws Exception;

}
