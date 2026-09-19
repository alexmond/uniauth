package org.alexmond.uniauth.config;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Decides what an unauthenticated caller is told, when HTTP Basic is in play.
 *
 * <p>
 * Three answers, not two, because the interesting case is neither a browser nor quite a
 * program. Installed naively, Basic answers an unauthenticated browser with a native
 * credential dialog instead of the chooser, which defeats the point of offering OAuth —
 * and a page's background {@code fetch()} opens that dialog just as readily as a
 * navigation does, <em>above</em> the page, before any JavaScript sees the 401. A front
 * end cannot suppress it, so it has to be decided here.
 *
 * <p>
 * Browsers say so themselves. Every current one labels its requests with
 * {@code Sec-Fetch-*}, which {@code curl} and the usual HTTP libraries do not send. So a
 * navigation gets the chooser, an XHR gets a bare {@code 401} the front end can act on,
 * and only a caller that did not identify itself is challenged. Clients that present
 * credentials up front never waited for a challenge anyway.
 *
 * <p>
 * This is published as a bean so that an application declaring its own, more specific
 * {@code SecurityFilterChain} — ordinary Spring Security, and something this starter
 * encourages — can reuse the rule rather than reproduce it. Inject it into the chain bean
 * and hand it to the Basic configurer:
 *
 * <pre>{@code
 * SecurityFilterChain apiChain(HttpSecurity http, UniAuthBasicEntryPoint entryPoint) throws Exception {
 *     return http.securityMatcher("/api/**")
 *         .authorizeHttpRequests((requests) -> requests.anyRequest().authenticated())
 *         .httpBasic((basic) -> basic.authenticationEntryPoint(entryPoint))
 *         .build();
 * }
 * }</pre>
 *
 * <p>
 * That chain bean carries its own {@code Order} ahead of the starter's, as usual.
 *
 * <p>
 * The bean exists whether or not {@code uniauth.http-basic.enabled} is set: that property
 * governs whether the <em>starter's own</em> chain installs Basic, while this is the rule
 * an application's chain asks for by name.
 */
public class UniAuthBasicEntryPoint implements AuthenticationEntryPoint {

	private final AuthenticationEntryPoint challenge;

	private final AuthenticationEntryPoint chooser;

	private final AuthenticationEntryPoint silent;

	private final List<String> paths;

	public UniAuthBasicEntryPoint(UniAuthProperties properties) {
		BasicAuthenticationEntryPoint basic = new BasicAuthenticationEntryPoint();
		basic.setRealmName("UniAuth");
		this.challenge = basic;
		this.chooser = new LoginUrlAuthenticationEntryPoint(properties.getLoginPage());
		this.silent = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
		this.paths = List.copyOf(properties.getHttpBasic().getPaths());
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
			throws IOException, ServletException {
		entryPointFor(request).commence(request, response, exception);
	}

	/**
	 * Which of the three answers a request gets.
	 *
	 * <p>
	 * {@code paths} scopes the <em>challenge</em>, not whether credentials are accepted.
	 * Scoping acceptance would mean narrowing the chain itself, and the starter's chain
	 * is the catch-all — it would stop UniAuth protecting everything outside those paths,
	 * which is a far larger change than the property appears to ask for. Presenting valid
	 * credentials anywhere is harmless; what the setting is for is keeping the browser's
	 * native dialog away from the pages humans visit.
	 * @param request the unauthenticated request
	 * @return the entry point that should answer it
	 */
	private AuthenticationEntryPoint entryPointFor(HttpServletRequest request) {
		if (!inScope(request)) {
			return this.chooser;
		}
		if (browserInitiated(request)) {
			if (navigating(request)) {
				return this.chooser;
			}
			return this.silent;
		}
		if (challengeFor(request)) {
			return this.challenge;
		}
		return this.chooser;
	}

	private boolean inScope(HttpServletRequest request) {
		return this.paths.isEmpty() || this.paths.stream()
			.anyMatch((pattern) -> PathPatternRequestMatcher.withDefaults().matcher(pattern).matches(request));
	}

	/**
	 * Whether the browser itself made this request.
	 *
	 * <p>
	 * Every current browser sends {@code Sec-Fetch-Site} on every request, and it is a
	 * forbidden header name, so a page cannot forge one. {@code curl} and the usual HTTP
	 * libraries send neither.
	 * @param request the request to classify
	 * @return true if a browser made it
	 */
	private static boolean browserInitiated(HttpServletRequest request) {
		return request.getHeader("Sec-Fetch-Site") != null || request.getHeader("Sec-Fetch-Mode") != null;
	}

	/**
	 * Whether the browser is going to a page, rather than fetching on one's behalf.
	 * @param request the request to classify
	 * @return true if this is a navigation
	 */
	private static boolean navigating(HttpServletRequest request) {
		return "navigate".equals(request.getHeader("Sec-Fetch-Mode"));
	}

	/**
	 * Whether a caller that did not identify itself should be challenged.
	 *
	 * <p>
	 * Only reached by clients sending no {@code Sec-Fetch-*} headers, which a browser
	 * always does — so this decides between programs and browsers too old to say. A
	 * program either presents credentials or does not ask for HTML.
	 * @param request the request to classify
	 * @return true if it should receive a Basic challenge
	 */
	private static boolean challengeFor(HttpServletRequest request) {
		return request.getHeader("Authorization") != null
				|| !String.valueOf(request.getHeader("Accept")).contains("text/html");
	}

}
