package org.alexmond.uniauth.autoconfigure;

import org.alexmond.uniauth.approval.ApprovalAuthoritiesFilter;
import org.alexmond.uniauth.approval.ApprovalAuthorizationManager;
import org.alexmond.uniauth.approval.PendingApprovalAccessDeniedHandler;
import org.alexmond.uniauth.config.UniAuthAuthorizationCustomizer;
import org.alexmond.uniauth.config.UniAuthProperties;
import org.alexmond.uniauth.provider.AuthProvider;
import org.alexmond.uniauth.provider.AuthProviderRegistry;
import org.alexmond.uniauth.provider.MechanismResolver;
import org.alexmond.uniauth.web.UniAuthLoginController;
import org.alexmond.uniauth.web.UniAuthProvidersController;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * Wires every enabled mechanism into a <em>single</em> {@link SecurityFilterChain}.
 *
 * <p>
 * This is the heart of the "universal" claim, and the part worth understanding before
 * changing anything here. Rather than one chain per mechanism — which would mean the
 * first matching chain wins and the others never run — there is one chain that has form
 * login, OAuth2 login and SAML login all installed on it. The form-based mechanisms
 * (internal, LDAP) are distinguished not by URL but by the {@code AuthenticationProvider}
 * chain: every provider bean is registered, and Spring Security tries each until one
 * authenticates the submitted credentials.
 *
 * <p>
 * Redirect-based mechanisms keep their own entry-point URLs, which is why the chooser
 * page only needs to render a link per registration.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(SecurityFilterChain.class)
// Off unless asked for. This library decides who may reach what, so installing a
// catch-all chain on the strength of being on the classpath is too strong a default:
// merely adding the dependency used to override an application's own authorization, in
// every profile and every test, before a line of integration was written. The symptom is
// a broadly-locked application rather than an obviously broken one, which is worse.
//
// It also matches the rest of the starter, where nothing acts without being asked:
// internal, ldap and approval all default to off.
@ConditionalOnProperty(prefix = "uniauth", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(UniAuthProperties.class)
@Import({ InternalAuthConfiguration.class, LdapAuthConfiguration.class, Oauth2AdaptersConfiguration.class,
		ApprovalConfiguration.class })
public class UniAuthAutoConfiguration {

	private static final Logger LOGGER = LoggerFactory.getLogger(UniAuthAutoConfiguration.class);

	/**
	 * The single answer to what a user can sign in with right now, read by both the
	 * chooser page and the providers endpoint.
	 * @param properties which mechanisms are switched on
	 * @param clientRegistrations OAuth2 registrations, from Spring Boot's own binding
	 * @param relyingParties SAML registrations, from Spring Boot's own binding
	 * @return the registry
	 */
	@Bean
	@ConditionalOnMissingBean
	public AuthProviderRegistry uniAuthProviderRegistry(UniAuthProperties properties,
			ObjectProvider<ClientRegistrationRepository> clientRegistrations,
			ObjectProvider<RelyingPartyRegistrationRepository> relyingParties) {
		return new AuthProviderRegistry(properties, clientRegistrations, relyingParties);
	}

	/**
	 * Serves the chooser page.
	 *
	 * <p>
	 * Registered as a bean rather than component-scanned, so
	 * {@code uniauth.enabled=false} genuinely backs off — a scan would pick the
	 * controller up regardless of the guard.
	 * @param registry supplies the providers the page offers
	 * @param properties supplies the paths the page posts to
	 * @return the controller
	 */
	@Bean
	@ConditionalOnMissingBean
	public UniAuthLoginController uniAuthLoginController(AuthProviderRegistry registry, UniAuthProperties properties) {
		return new UniAuthLoginController(registry, properties);
	}

	/**
	 * Serves the same provider list as JSON, for a front end rendering its own chooser.
	 * @param registry supplies the providers
	 * @return the controller
	 */
	@Bean
	@ConditionalOnMissingBean
	public UniAuthProvidersController uniAuthProvidersController(AuthProviderRegistry registry) {
		return new UniAuthProvidersController(registry);
	}

	/**
	 * Available whether or not the approval gate is on: knowing which provider answered
	 * is useful to any application, not just to an approval decision.
	 * @return the resolver
	 */
	@Bean
	@ConditionalOnMissingBean
	public MechanismResolver uniAuthMechanismResolver() {
		return new MechanismResolver();
	}

	/**
	 * The catch-all chain, deliberately conditional on its own bean <em>name</em> rather
	 * than on {@code SecurityFilterChain} as a type.
	 *
	 * <p>
	 * Backing off whenever the application declared any chain at all was too blunt:
	 * adding a second, more specific chain — for an authorization server's endpoints, or
	 * an API path — is ordinary Spring Security, and it should not cost you every
	 * mechanism this starter wires. Chains are matched in order and this one has the
	 * default lowest precedence, so a more specific chain declared by the application
	 * runs first and this one catches the rest.
	 *
	 * <p>
	 * To replace it outright rather than add to it, name your bean
	 * {@code uniAuthSecurityFilterChain}.
	 * @param http the builder this chain is assembled on
	 * @param properties paths, and which mechanisms to install
	 * @param registry decides whether a form login is installed at all
	 * @param authenticationProviders every {@code AuthenticationProvider} bean,
	 * registered in order so the form falls through them — this is what lets local
	 * break-glass accounts sit beside a directory
	 * @param clientRegistrations OAuth2 registrations; login is installed only when some
	 * exist, since a chain with no registration would 404 its own callback
	 * @param relyingParties SAML registrations, on the same condition
	 * @param approvalManager the approval gate, replacing {@code .authenticated()} when
	 * enabled; absent otherwise
	 * @param authorizationCustomizers application-supplied rules, applied in order before
	 * the catch-all so the chain can express more than "permitted or authenticated"
	 * @param entryPoint an application-supplied entry point, used instead of redirecting
	 * to the chooser — this is how an API-first application answers 401
	 * @return the chain
	 * @throws Exception if the chain cannot be built
	 */
	@Bean
	@ConditionalOnMissingBean(name = "uniAuthSecurityFilterChain")
	public SecurityFilterChain uniAuthSecurityFilterChain(HttpSecurity http, UniAuthProperties properties,
			AuthProviderRegistry registry, ObjectProvider<AuthenticationProvider> authenticationProviders,
			ObjectProvider<ClientRegistrationRepository> clientRegistrations,
			ObjectProvider<RelyingPartyRegistrationRepository> relyingParties,
			ObjectProvider<ApprovalAuthorizationManager> approvalManager,
			ObjectProvider<ApprovalAuthoritiesFilter> approvalAuthorities,
			ObjectProvider<UniAuthAuthorizationCustomizer> authorizationCustomizers,
			ObjectProvider<AuthenticationEntryPoint> entryPoint) throws Exception {

		List<String> permitted = new ArrayList<>(
				List.of(properties.getLoginPage(), properties.getProvidersEndpoint(), "/error"));
		permitted.addAll(properties.getPublicPaths());

		ApprovalAuthorizationManager approval = approvalManager.getIfAvailable();
		if (approval != null) {
			// The waiting page has to be reachable by the very people the gate is keeping
			// out, or the redirect loops.
			permitted.add(properties.getApproval().getPendingPage());
		}

		authorize(http, permitted, authorizationCustomizers, approval);
		httpBasic(http, properties);

		AuthenticationEntryPoint customEntryPoint = entryPoint.getIfAvailable();
		if (approval != null || customEntryPoint != null) {
			http.exceptionHandling((exceptions) -> {
				if (approval != null) {
					exceptions.accessDeniedHandler(
							new PendingApprovalAccessDeniedHandler(properties.getApproval().getPendingPage()));
				}
				// An API-first application declares one of these to get 401 instead of a
				// redirect to a page its front end has no use for.
				if (customEntryPoint != null) {
					exceptions.authenticationEntryPoint(customEntryPoint);
				}
			});
		}

		// Internal and LDAP both land here; order of the provider beans decides who is
		// asked first.
		authenticationProviders.orderedStream().forEach(http::authenticationProvider);

		if (registry.hasFormProvider()) {
			http.formLogin((form) -> form.loginPage(properties.getLoginPage())
				.defaultSuccessUrl(properties.getDefaultSuccessUrl(), true)
				.permitAll());
		}

		if (properties.getOauth2().isEnabled() && clientRegistrations.getIfAvailable() != null) {
			http.oauth2Login((oauth2) -> oauth2.loginPage(properties.getLoginPage())
				.defaultSuccessUrl(properties.getDefaultSuccessUrl(), true));
		}

		if (properties.getSaml().isEnabled() && relyingParties.getIfAvailable() != null) {
			http.saml2Login((saml2) -> saml2.loginPage(properties.getLoginPage())
				.defaultSuccessUrl(properties.getDefaultSuccessUrl(), true));
			http.saml2Logout((withDefaults) -> {
			});
		}

		http.logout((logout) -> logout.logoutSuccessUrl(properties.getLogoutSuccessUrl()).permitAll());

		// Before AuthorizationFilter, or the roles arrive after the decision that needed
		// them. The authentication is already on the context by this point — it is loaded
		// near the start of the chain — so this only has to add to it.
		ApprovalAuthoritiesFilter authorities = approvalAuthorities.getIfAvailable();
		if (authorities != null) {
			http.addFilterBefore(authorities, AuthorizationFilter.class);
		}

		SecurityFilterChain chain = http.build();
		logInstalled(properties, registry, approval != null);
		return chain;
	}

	/**
	 * Says, once, in the boot log, that this library is now deciding authorization.
	 *
	 * <p>
	 * Installing a catch-all chain is a large thing to do quietly. Even with
	 * {@code uniauth.enabled} now explicit, the default rule is worth stating: an
	 * application whose own rules stopped applying should be able to find out why by
	 * reading its startup log rather than by bisecting its dependencies.
	 */
	/**
	 * Installs HTTP Basic for callers that are not browsers.
	 *
	 * <p>
	 * Basic answers the form-based mechanisms only. The redirect-based ones have no
	 * password to present, so the question does not arise for them — a caller sending
	 * {@code Authorization: Basic} is presenting credentials the internal store or a
	 * directory can check.
	 *
	 * <p>
	 * The entry point is the part worth getting right. Installed naively, an
	 * unauthenticated browser receives a native credential dialog instead of the chooser,
	 * which defeats the point of offering OAuth. So the Basic challenge is delegated: it
	 * answers requests that look like a program's — an explicit {@code Authorization}
	 * header, or an {@code Accept} that does not ask for HTML — and everything else falls
	 * through to whatever the chain would otherwise have done.
	 */
	private static void httpBasic(HttpSecurity http, UniAuthProperties properties) throws Exception {
		UniAuthProperties.HttpBasic basic = properties.getHttpBasic();
		if (!basic.isEnabled()) {
			return;
		}
		http.httpBasic((configurer) -> configurer.authenticationEntryPoint(apiOnlyBasicEntryPoint(properties)));
	}

	/**
	 * Challenges programs, redirects browsers.
	 */
	private static AuthenticationEntryPoint apiOnlyBasicEntryPoint(UniAuthProperties properties) {
		BasicAuthenticationEntryPoint basic = new BasicAuthenticationEntryPoint();
		basic.setRealmName("UniAuth");
		LoginUrlAuthenticationEntryPoint chooser = new LoginUrlAuthenticationEntryPoint(properties.getLoginPage());
		List<String> paths = properties.getHttpBasic().getPaths();
		return (request, response, exception) -> {
			if (challengeFor(request, paths)) {
				basic.commence(request, response, exception);
			}
			else {
				chooser.commence(request, response, exception);
			}
		};
	}

	/**
	 * Whether to answer with a Basic challenge rather than the chooser.
	 *
	 * <p>
	 * {@code paths} scopes the <em>challenge</em>, not whether credentials are accepted.
	 * Scoping acceptance would mean narrowing the chain itself, and this chain is the
	 * catch-all — it would stop UniAuth protecting everything outside those paths, which
	 * is a far larger change than the property appears to ask for. Presenting valid
	 * credentials anywhere is harmless; what the setting is for is keeping the browser's
	 * native dialog away from the pages humans visit.
	 */
	private static boolean challengeFor(HttpServletRequest request, List<String> paths) {
		if (!paths.isEmpty() && paths.stream()
			.noneMatch((pattern) -> PathPatternRequestMatcher.withDefaults().matcher(pattern).matches(request))) {
			return false;
		}
		// A program either presents credentials or does not ask for HTML. A browser
		// asking for a page gets the chooser, which is the point of offering OAuth.
		return request.getHeader("Authorization") != null
				|| !String.valueOf(request.getHeader("Accept")).contains("text/html");
	}

	/**
	 * Permitted paths, then the application's own rules, then the catch-all.
	 *
	 * <p>
	 * Order is the whole design here: the first matching rule wins, so a rule contributed
	 * after {@code anyRequest()} would never be reached, and one contributed before the
	 * permitted paths could lock a login page.
	 */
	private static void authorize(HttpSecurity http, List<String> permitted,
			ObjectProvider<UniAuthAuthorizationCustomizer> customizers, ApprovalAuthorizationManager approval)
			throws Exception {
		http.authorizeHttpRequests((requests) -> {
			requests.requestMatchers(permitted.toArray(String[]::new)).permitAll();
			customizers.orderedStream().forEach((customizer) -> customizer.customize(requests));
			if (approval != null) {
				// Replaces .authenticated(): the manager refuses anonymous requests too,
				// so the entry point still redirects to the chooser as before.
				requests.anyRequest().access(approval);
			}
			else {
				requests.anyRequest().authenticated();
			}
		});
	}

	private static void logInstalled(UniAuthProperties properties, AuthProviderRegistry registry,
			boolean approvalEnabled) {
		String mechanisms = registry.providers()
			.stream()
			.map(AuthProvider::id)
			.collect(java.util.stream.Collectors.joining(", "));
		LOGGER.info(
				"UniAuth installed a SecurityFilterChain: every request needs {}, except {} which are permitted. "
						+ "Providers: [{}]. Set uniauth.enabled=false to back off entirely.",
				approvalEnabled ? "authentication and approval" : "authentication",
				properties.getPublicPaths().isEmpty() ? "none" : properties.getPublicPaths(),
				mechanisms.isEmpty() ? "none configured" : mechanisms);
	}

}
