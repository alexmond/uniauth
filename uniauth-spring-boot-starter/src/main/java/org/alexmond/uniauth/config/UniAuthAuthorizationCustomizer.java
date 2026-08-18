package org.alexmond.uniauth.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

/**
 * Contributes authorization rules to UniAuth's chain, without owning it.
 *
 * <p>
 * The single chain is what makes four mechanisms reachable at once, but it offered
 * exactly one authorization shape: {@code uniauth.public-paths} are permitted and
 * everything else is authenticated. An application whose rules are a different shape — a
 * role on an admin area, a method-scoped rule, anything keyed on something other than a
 * path string — had no way in.
 *
 * <p>
 * Neither escape hatch fitted. Replacing the chain costs every mechanism the starter
 * wires, which is the entire value. Adding a higher-precedence chain works, but separates
 * the rules from the mechanisms that satisfy them, and forces per-chain settings like
 * CSRF and cache-control to be repeated — where any drift between the copies is a bug
 * nobody notices.
 *
 * <p>
 * Declare one or more as beans. Each is applied in
 * {@link org.springframework.core.Ordered} order, <em>before</em> the catch-all, because
 * the first matching rule wins and a rule added after {@code anyRequest()} would never be
 * reached.
 *
 * <p>
 * The registry is Spring Security's own, so anything expressible there is expressible
 * here:
 *
 * <pre>
 * &#64;Bean
 * UniAuthAuthorizationCustomizer adminRules() {
 *     return (rules) -&gt; rules
 *         .requestMatchers("/dev", "/review.html").hasRole("ADMIN")
 *         .requestMatchers(HttpMethod.POST, "/api/feedback").authenticated()
 *         .requestMatchers((request) -&gt; request.getLocalPort() == 9090).permitAll();
 * };
 * </pre>
 */
@FunctionalInterface
public interface UniAuthAuthorizationCustomizer {

	/**
	 * Adds rules to the chain.
	 * @param rules Spring Security's registry, positioned after the permitted paths and
	 * before the catch-all
	 */
	void customize(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry rules);

}
